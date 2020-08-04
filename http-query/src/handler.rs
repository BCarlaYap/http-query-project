use curl::easy::{Handler, InfoType, ReadError, WriteError};
use log::{error, info};
use std::str;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHandler {
    pub response_header: Vec<u8>,
    pub response_body: Vec<u8>,
    pub data_limit: usize,
    calculated_size: usize,
    verbose: bool,
}

impl ResponseHandler {
    pub fn new(data_limit: usize, verbose: bool) -> ResponseHandler {
        ResponseHandler {
            response_header: vec![],
            response_body: vec![],
            data_limit,
            calculated_size: 0,
            verbose,
        }
    }

    pub fn update_calculated_size(&mut self, consumed: usize) { self.calculated_size = consumed; }

    pub fn add_calculated_size(&mut self, consumed: usize) {
        self.calculated_size = &self.calculated_size + consumed;
    }

    pub fn calculated_size(&self) -> usize { self.calculated_size }
}

impl Handler for ResponseHandler {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.response_body.extend_from_slice(data);

        self.calculated_size = self.calculated_size + data.len();

        if self.calculated_size > self.data_limit {
            error!("{} bytes exceeded limit of {}", &self.calculated_size, &self.data_limit);
            return Ok(0);
        }
        Ok(data.len())
    }

    fn read(&mut self, data: &mut [u8]) -> Result<usize, ReadError> {
        self.calculated_size = self.calculated_size + data.len();

        if self.calculated_size > self.data_limit {
            error!("{} bytes exceeded limit of {}", &self.calculated_size, &self.data_limit);
            return Err(ReadError::Abort);
        }

        Ok(0)
    }

    fn debug(&mut self, kind: InfoType, data: &[u8]) {
        let prefix = match kind {
            InfoType::Text => "*",
            InfoType::HeaderIn => "<",
            InfoType::HeaderOut => ">",
            InfoType::DataIn => "{\n",
            InfoType::DataOut => "}\n",
            InfoType::SslDataIn => "[\n",
            InfoType::SslDataOut => "]\n",
            InfoType::__Nonexhaustive => "xxxxxxxxx",
        };


        if self.verbose {
            drop(print!("{} ", prefix))
        }

        match str::from_utf8(data) {
            Ok(s) => {
                if self.verbose {
                    drop(println!("EHEHEHEHEHE -> {}", s))
                }
            }
            Err(_) => {
                self.calculated_size = self.calculated_size + data.len();
                if self.verbose {
                    drop(println!("{} bytes of data", data.len()))
                }
            }
        };
    }


    fn header(&mut self, data: &[u8]) -> bool {
        self.response_header.extend_from_slice(data);
        self.calculated_size = self.calculated_size + data.len();

        if self.calculated_size > self.data_limit {
            error!("{} bytes exceeded limit of {}", &self.calculated_size, &self.data_limit);
            return false;
        }
        true
    }
}
