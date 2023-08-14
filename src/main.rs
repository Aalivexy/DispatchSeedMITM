#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use anyhow::{Context, Result};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request},
    *,
};
use rustls_pemfile as pemfile;
use std::{
    cell::RefCell,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    rc::Rc,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex,
    },
};

use libui::controls::*;
use libui::prelude::*;

const CERT_PATH: &str = "cert.crt";
const KEY_PATH: &str = "private.key";

#[derive(Clone)]
struct Handler(Arc<Mutex<Sender<String>>>);

#[async_trait::async_trait]
impl HttpHandler for Handler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if let Some(query) = req.uri().query() {
            if let Some(seed) = query
                .split('&')
                .find(|x| x.contains("dispatchSeed") || x.contains("dispatch_seed"))
            {
                self.0
                    .lock()
                    .unwrap()
                    .send(format!(
                        "{}: {seed}",
                        req.uri().host().unwrap_or("unknown host")
                    ))
                    .unwrap();
                dbg!(&req);
            }
        }
        req.into()
    }
}

struct State {
    cert_path: String,
    key_path: String,
    socket_addr: String,
    proxy_started: Option<tokio::sync::mpsc::Sender<()>>,
    log_rx: Vec<Receiver<String>>,
}

fn main() {
    let proxy_backup = sysproxy::Sysproxy::get_system_proxy().unwrap();
    let ui = UI::init().unwrap();

    let state = Rc::new(RefCell::new(State {
        cert_path: {
            if std::path::Path::new(CERT_PATH).exists() {
                CERT_PATH
            } else {
                ""
            }
            .to_owned()
        },
        key_path: {
            if std::path::Path::new(KEY_PATH).exists() {
                KEY_PATH
            } else {
                ""
            }
            .to_owned()
        },
        socket_addr: { "127.0.0.1:13303".to_owned() },
        proxy_started: None,
        log_rx: vec![],
    }));

    let mut win = Window::new(&ui.clone(), "MITM Proxy", 300, 400, WindowType::NoMenubar);
    win.on_closing(&ui, move |win| {
        proxy_backup
            .set_system_proxy()
            .context("Failed to set system proxy")
            .unwrap();
        unsafe { win.destroy() }
        std::process::exit(0);
    });
    let mut vbox = VerticalBox::new();
    vbox.set_padded(true);

    let mut log = MultilineEntry::new_nonwrapping();
    log.set_readonly(true);

    let mut cert_line = VerticalBox::new();
    let cert_label = Label::new("Certification Path");
    let mut cert_ctrl = HorizontalBox::new();
    let mut cert_input: Entry = Entry::new();
    cert_input.set_value(&state.borrow().cert_path);
    let mut cert_button = Button::new(" Select File ");
    cert_button.on_clicked({
        let win = win.clone();
        let state = state.clone();
        let mut cert_input = cert_input.clone();
        move |_| {
            if let Some(path) = win.open_file() {
                match path.canonicalize() {
                    Ok(p) => {
                        let p = p.to_str().unwrap();
                        state.borrow_mut().cert_path = p.to_string();
                        cert_input.set_value(p);
                    }
                    Err(e) => win.modal_err("ERROR", &e.to_string()),
                }
            }
        }
    });
    cert_ctrl.append(cert_input.clone(), LayoutStrategy::Stretchy);
    cert_ctrl.append(cert_button, LayoutStrategy::Compact);
    cert_line.append(cert_label, LayoutStrategy::Compact);
    cert_line.append(cert_ctrl, LayoutStrategy::Stretchy);

    let mut key_line = VerticalBox::new();
    let key_label = Label::new("Private Key Path");
    let mut key_ctrl = HorizontalBox::new();
    let mut key_input: Entry = Entry::new();
    key_input.set_value(&state.borrow().key_path);
    let mut key_button = Button::new(" Select File ");
    key_button.on_clicked({
        let win = win.clone();
        let state = state.clone();
        let mut key_input = key_input.clone();
        move |_| {
            if let Some(path) = win.open_file() {
                match path.canonicalize() {
                    Ok(p) => {
                        let p = p.to_str().unwrap();
                        state.borrow_mut().key_path = p.to_string();
                        key_input.set_value(p);
                    }
                    Err(e) => win.modal_err("ERROR", &e.to_string()),
                }
            }
        }
    });
    key_ctrl.append(key_input.clone(), LayoutStrategy::Stretchy);
    key_ctrl.append(key_button, LayoutStrategy::Compact);
    key_line.append(key_label, LayoutStrategy::Compact);
    key_line.append(key_ctrl, LayoutStrategy::Stretchy);

    let mut cert_key = VerticalBox::new();
    cert_key.append(cert_line, LayoutStrategy::Compact);
    cert_key.append(key_line, LayoutStrategy::Compact);
    let mut cert_key_group = Group::new("Certificate and Private Key");
    cert_key_group.set_child(cert_key);

    let mut gen_trust_line = VerticalBox::new();
    let gen_trust_label =
        Label::new("Generating and trusting is only required for the first operation");
    let mut gen_trust_ctrl = HorizontalBox::new();
    gen_trust_ctrl.set_padded(true);
    let mut gen_btn = Button::new("Generate CA");
    gen_btn.on_clicked({
        let win = win.clone();
        let mut cert_input = cert_input.clone();
        let mut key_input = key_input.clone();
        move |_| {
            match gen_ca(&win) {
                Ok(_) => {
                    cert_input.set_value(CERT_PATH);
                    key_input.set_value(KEY_PATH);
                }
                Err(e) => win.modal_err("ERROR", &e.to_string()),
            };
        }
    });
    let mut trust_btn = Button::new("Trust CA");
    trust_btn.on_clicked({
        let win = win.clone();
        move |_| {
            match trust_ca() {
                Ok(_) => {
                    cert_input.set_value(CERT_PATH);
                    key_input.set_value(KEY_PATH);
                }
                Err(e) => win.modal_err("ERROR", &e.to_string()),
            };
        }
    });
    gen_trust_ctrl.append(gen_btn, LayoutStrategy::Stretchy);
    gen_trust_ctrl.append(trust_btn, LayoutStrategy::Stretchy);
    gen_trust_line.append(gen_trust_ctrl, LayoutStrategy::Stretchy);
    gen_trust_line.append(gen_trust_label, LayoutStrategy::Compact);

    let mut socket_addr_line = VerticalBox::new();
    let socket_addr_label = Label::new("Proxy listening address:");
    let mut socket_addr_ctrl = HorizontalBox::new();
    socket_addr_ctrl.set_padded(true);
    let mut socket_addr_input: Entry = Entry::new();
    socket_addr_input.set_value(&state.borrow().socket_addr);
    let mut proxy_start_btn = Button::new("Start Proxy");
    proxy_start_btn.on_clicked({
        let win = win.clone();
        let state = state.clone();
        let addr = socket_addr_input.clone();
        move |btn| {
            let mut state = state.borrow_mut();
            match &state.proxy_started {
                Some(tx) => {
                    match tx.blocking_send(()) {
                        Ok(_) => {
                            btn.set_text("Start Proxy");
                            state.proxy_started = None;
                        }
                        Err(e) => win.modal_err("ERROR", &format!("Failed to stop the proxy: {e}")),
                    };
                }
                None => {
                    let cert_path = match PathBuf::from(&state.cert_path).canonicalize() {
                        Ok(p) => p,
                        Err(e) => {
                            win.modal_err("ERROR", &format!("Failed to parse cert path: {e}"));
                            return;
                        }
                    };
                    let key_path = match PathBuf::from(&state.key_path).canonicalize() {
                        Ok(p) => p,
                        Err(e) => {
                            win.modal_err("ERROR", &format!("Failed to parse key path: {e}"));
                            return;
                        }
                    };
                    let socket_addr = match addr
                        .value()
                        .replace("localhost", "127.0.0.1")
                        .to_socket_addrs()
                    {
                        Ok(mut addr) => addr.next().unwrap(),
                        Err(e) => {
                            win.modal_err("ERROR", &format!("Failed to parse socket address: {e}"));
                            return;
                        }
                    };

                    let (tx, rx) = tokio::sync::mpsc::channel(8);
                    let (log_tx, log_rx) = std::sync::mpsc::channel();
                    std::thread::spawn(move || {
                        match start_proxy(rx, cert_path, key_path, socket_addr, log_tx.clone()) {
                            Ok(_) => {}
                            Err(e) => {
                                log_tx.send(format!("Failed to start proxy: {e}")).unwrap();
                            }
                        }
                    });
                    state.log_rx.push(log_rx);
                    btn.set_text("Stop Proxy");
                    state.proxy_started = Some(tx);
                }
            }
        }
    });
    socket_addr_ctrl.append(socket_addr_input, LayoutStrategy::Stretchy);
    socket_addr_ctrl.append(proxy_start_btn, LayoutStrategy::Stretchy);
    socket_addr_line.append(socket_addr_label, LayoutStrategy::Compact);
    socket_addr_line.append(socket_addr_ctrl, LayoutStrategy::Compact);

    vbox.append(cert_key_group, LayoutStrategy::Compact);
    vbox.append(gen_trust_line, LayoutStrategy::Compact);
    vbox.append(HorizontalSeparator::new(), LayoutStrategy::Compact);
    vbox.append(socket_addr_line, LayoutStrategy::Compact);
    vbox.append(log.clone(), LayoutStrategy::Stretchy);

    win.set_child(vbox);
    win.show();

    let mut event_loop = ui.event_loop();
    event_loop.on_tick({
        let mut log = log.clone();
        let state = state.clone();
        move || {
            let state = state.borrow();
            for rx in &state.log_rx {
                if let Ok(s) = rx.try_recv() {
                    log.append(&(s + "\n"));
                }
            }
        }
    });
    event_loop.run();
}

fn gen_ca(win: &Window) -> Result<()> {
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
        KeyUsagePurpose,
    };

    let path = std::env::current_dir()?;
    let cert_path = path.join(CERT_PATH);
    let key_path = path.join(KEY_PATH);
    if std::fs::canonicalize(&cert_path).is_ok() && std::fs::canonicalize(&key_path).is_ok() {
        win.modal_msg("Info", "The CA has been generated!");
        return Ok(());
    }

    let mut params = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "MITM");
    distinguished_name.push(DnType::OrganizationName, "MITM");
    distinguished_name.push(DnType::CountryName, "CN");
    distinguished_name.push(DnType::LocalityName, "CN");
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = Certificate::from_params(params).unwrap();

    std::fs::write(cert_path, ca.serialize_pem().unwrap())
        .context("Failed to write certificate")?;
    std::fs::write(key_path, ca.serialize_private_key_pem())
        .context("Failed to write private key")?;
    Ok(())
}

fn trust_ca() -> Result<()> {
    let path = std::fs::canonicalize(CERT_PATH)?
        .to_string_lossy()
        .into_owned();
    runas::Command::new("cmd")
        .show(true)
        .args(&["/c", "certutil", "-addstore", "Root", &path, "&&", "pause"])
        .status()?;
    Ok(())
}

fn start_proxy(
    rx: tokio::sync::mpsc::Receiver<()>,
    cert_path: PathBuf,
    key_path: PathBuf,
    socket_addr: SocketAddr,
    log_tx: Sender<String>,
) -> Result<()> {
    let proxy_backup = sysproxy::Sysproxy::get_system_proxy().unwrap();
    async fn sg(mut rx: tokio::sync::mpsc::Receiver<()>) {
        rx.recv().await.unwrap();
    }
    let mut ca_cert_bytes: &[u8] = &std::fs::read(cert_path).unwrap();
    let mut private_key_bytes: &[u8] = &std::fs::read(key_path).unwrap();

    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .context("Failed to parse CA certificate")?
            .remove(0),
    );
    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .context("Failed to parse private key")?
            .remove(0),
    );

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .context("Failed to create Certificate Authority")?;

    let proxy = Proxy::builder()
        .with_addr(socket_addr)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(Handler(Arc::new(Mutex::new(log_tx))))
        .build();

    sysproxy::Sysproxy {
        enable: true,
        host: socket_addr.ip().to_string(),
        port: socket_addr.port(),
        bypass: "localhost;127.*;10.*;192.168.*".to_owned(),
    }
    .set_system_proxy()
    .context("Failed to set system proxy")?;

    dbg!("starting...");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            if let Err(e) = proxy.start(sg(rx)).await {
                println!("{}", e);
            }
        });

    dbg!("ending...");
    proxy_backup
        .set_system_proxy()
        .context("Failed to reset system proxy")?;
    Ok(())
}
