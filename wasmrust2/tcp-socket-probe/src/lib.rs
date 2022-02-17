use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::net::TcpStream;
use log::trace;


#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(TcpSocketProbeRoot {
            port: String::new(),
        })
    });
}

struct TcpSocketProbeRoot {
    port: String,
}

impl Context for TcpSocketProbeRoot {}

impl RootContext for TcpSocketProbeRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        //if let Some(config_bytes) = self.get_plugin_configuration() {
        //    self.port = String::from_utf8(config_bytes).unwrap()
        //}
        self.port = String::from("3306");
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(TcpSocketProbe {
            port: self.port.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct TcpSocketProbe {
    port: String,
}

impl Context for TcpSocketProbe {}

impl HttpContext for TcpSocketProbe {
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        // Note: the port would not be hardcoded
        trace!("made it here");
        if let Ok(stream) = TcpStream::connect("127.0.0.1:3306") {
            trace!("made it here!!!");
            self.send_http_response(
                200,
                vec![("Powered-By", "proxy-wasm")],
                Some(b"Connection established\n"),
            );
        } else {
            trace!("made it here :(");
            self.send_http_response(
                403,
                vec![("Powered-By", "proxy-wasm")],
                Some(b"Failed to Establish Connection\n"),
            );
        }
        Action::Pause
    }
}