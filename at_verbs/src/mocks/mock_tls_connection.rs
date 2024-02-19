use at_tls::{at_server_addr::AtServerAddr, tls_connection_trait};

// Mock implementation for TlsConnection (copied from ChatGPT)
pub struct MockTlsConnection {
    // Add more fields as needed to simulate state and behavior
    pub written_data: Vec<u8>, // For inspecting what was written
    pub to_be_read: Vec<u8>,   // Data that will be "read" by the client
}

impl std::io::Read for MockTlsConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Implement mock read behavior here
        let len = std::cmp::min(buf.len(), self.to_be_read.len());
        buf[..len].copy_from_slice(&self.to_be_read[..len]);
        self.to_be_read.drain(..len);
        Ok(len)
    }
}

impl std::io::Write for MockTlsConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Record data that is being written for inspection
        self.written_data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tls_connection_trait::TlsConnection for MockTlsConnection {
    fn connect(_address: &AtServerAddr) -> std::io::Result<Self>
    where
        Self: Sized,
    {
        // Return a mock object. Customize as necessary for the test scenario.
        Ok(Self {
            written_data: vec![],
            to_be_read: vec![],
        })
    }
}
