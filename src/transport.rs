pub trait Transport {
    fn read(&mut self, buf: &mut Vec<u8>) -> Result<usize, std::io::Error>;
    fn write(&mut self, buf: Vec<u8>) -> Result<(), std::io::Error>;
}
