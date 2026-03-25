const END: u8 = 0xC0;
const ESC: u8 = 0xDB;
const ESC_END: u8 = 0xDC;
const ESC_ESC: u8 = 0xDD;

#[allow(dead_code)]
const MAX_FRAME_SIZE: usize = 1280;
#[derive(Debug, PartialEq)]
pub enum DecodeError {
    FrameTooLong,
}

enum DecodeState {
    Normal,
    Escaped,
}

pub struct SlipDecoder {
    state: DecodeState,
    pos: usize,
}

impl SlipDecoder {
    pub const fn new() -> Self {
        Self {
            state: DecodeState::Normal,
            pos: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = DecodeState::Normal;
        self.pos = 0;
    }

    pub fn feed<'a>(
        &mut self,
        byte: u8,
        buf: &'a mut [u8],
    ) -> Result<Option<&'a [u8]>, DecodeError> {
        match self.state {
            DecodeState::Normal => match byte {
                END => {
                    if self.pos > 0 {
                        let frame = &buf[..self.pos];
                        self.pos = 0;
                        Ok(Some(frame))
                    } else {
                        Ok(None)
                    }
                }
                ESC => {
                    self.state = DecodeState::Escaped;
                    Ok(None)
                }
                b => {
                    if self.pos >= buf.len() {
                        self.pos = 0;
                        self.state = DecodeState::Normal;
                        return Err(DecodeError::FrameTooLong);
                    }
                    buf[self.pos] = b;
                    self.pos += 1;
                    Ok(None)
                }
            },
            DecodeState::Escaped => {
                let decoded = match byte {
                    ESC_END => END,
                    ESC_ESC => ESC,
                    _ => {
                        self.state = DecodeState::Normal;
                        self.pos = 0;
                        return Err(DecodeError::FrameTooLong);
                    }
                };
                if self.pos >= buf.len() {
                    self.pos = 0;
                    self.state = DecodeState::Normal;
                    return Err(DecodeError::FrameTooLong);
                }
                buf[self.pos] = decoded;
                self.pos += 1;
                self.state = DecodeState::Normal;
                Ok(None)
            }
        }
    }

    pub fn encode(input: &[u8], output: &mut [u8]) -> usize {
        let mut out_pos = 0;
        if out_pos < output.len() {
            output[out_pos] = END;
            out_pos += 1;
        }
        for &b in input {
            match b {
                END => {
                    if out_pos + 1 < output.len() {
                        output[out_pos] = ESC;
                        output[out_pos + 1] = ESC_END;
                        out_pos += 2;
                    }
                }
                ESC => {
                    if out_pos + 1 < output.len() {
                        output[out_pos] = ESC;
                        output[out_pos + 1] = ESC_ESC;
                        out_pos += 2;
                    }
                }
                _ => {
                    if out_pos < output.len() {
                        output[out_pos] = b;
                        out_pos += 1;
                    }
                }
            }
        }
        if out_pos < output.len() {
            output[out_pos] = END;
            out_pos += 1;
        }
        out_pos
    }
}
