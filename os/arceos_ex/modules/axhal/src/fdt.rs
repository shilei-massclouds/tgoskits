//! Minimal flattened device tree reader for early boot.

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const FDT_HEADER_SIZE: usize = 40;

#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    blob: &'a [u8],
    struct_block: &'a [u8],
    strings_block: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct Node<'a> {
    pub name: &'a str,
    pub depth: usize,
    props_start: usize,
    props_end: usize,
    fdt: Fdt<'a>,
}

impl<'a> Fdt<'a> {
    pub fn from_bytes(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < FDT_HEADER_SIZE || read_be_u32_at(blob, 0)? != FDT_MAGIC {
            return None;
        }

        let off_dt_struct = usize::try_from(read_be_u32_at(blob, 8)?).ok()?;
        let off_dt_strings = usize::try_from(read_be_u32_at(blob, 12)?).ok()?;
        let size_dt_strings = usize::try_from(read_be_u32_at(blob, 32)?).ok()?;
        let size_dt_struct = usize::try_from(read_be_u32_at(blob, 36)?).ok()?;
        let struct_end = off_dt_struct.checked_add(size_dt_struct)?;
        let strings_end = off_dt_strings.checked_add(size_dt_strings)?;
        if struct_end > blob.len() || strings_end > blob.len() {
            return None;
        }

        let fdt = Self {
            blob,
            struct_block: &blob[off_dt_struct..struct_end],
            strings_block: &blob[off_dt_strings..strings_end],
        };
        if !fdt.nodes().any(|node| node.depth == 0 && node.name == "/") {
            return None;
        }

        Some(fdt)
    }

    pub fn nodes(&self) -> NodeIter<'a> {
        NodeIter {
            fdt: *self,
            offset: 0,
            depth: 0,
            done: false,
        }
    }

    pub fn find_node(&self, path: &str) -> Option<Node<'a>> {
        self.nodes().find(|node| node.path_eq(path))
    }

    fn string_at(&self, offset: usize) -> Option<&'a str> {
        let raw = cstr_at(self.strings_block, offset)?;
        core::str::from_utf8(raw).ok()
    }
}

impl<'a> Node<'a> {
    pub fn property(&self, name: &str) -> Option<&'a [u8]> {
        let mut offset = self.props_start;
        while offset < self.props_end {
            let token = take_token(self.fdt.struct_block, &mut offset)?;
            match token {
                FDT_PROP => {
                    let len =
                        usize::try_from(take_token(self.fdt.struct_block, &mut offset)?).ok()?;
                    let nameoff =
                        usize::try_from(take_token(self.fdt.struct_block, &mut offset)?).ok()?;
                    let value_end = offset.checked_add(len)?;
                    if value_end > self.fdt.struct_block.len() {
                        return None;
                    }
                    let value = &self.fdt.struct_block[offset..value_end];
                    offset = align_up_4(value_end)?;
                    if self.fdt.string_at(nameoff)? == name {
                        return Some(value);
                    }
                }
                FDT_NOP => {}
                _ => return None,
            }
        }

        None
    }

    pub fn prop_str_eq(&self, name: &str, value: &[u8]) -> bool {
        self.property(name)
            .is_some_and(|raw| raw.split(|byte| *byte == 0).next() == Some(value))
    }

    fn path_eq(&self, path: &str) -> bool {
        if self.depth == 0 {
            path == "/"
        } else if let Some(name) = path.strip_prefix('/') {
            self.name == name
        } else {
            false
        }
    }
}

pub struct NodeIter<'a> {
    fdt: Fdt<'a>,
    offset: usize,
    depth: usize,
    done: bool,
}

impl<'a> Iterator for NodeIter<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let token = take_token(self.fdt.struct_block, &mut self.offset)?;
            match token {
                FDT_BEGIN_NODE => {
                    let name_raw = cstr_at(self.fdt.struct_block, self.offset)?;
                    let name = if name_raw.is_empty() {
                        "/"
                    } else {
                        core::str::from_utf8(name_raw).ok()?
                    };
                    self.offset = align_up_4(self.offset.checked_add(name_raw.len() + 1)?)?;
                    let props_start = self.offset;
                    let props_end = skip_props(self.fdt.struct_block, &mut self.offset)?;
                    let depth = self.depth;
                    self.depth = self.depth.checked_add(1)?;
                    return Some(Node {
                        name,
                        depth,
                        props_start,
                        props_end,
                        fdt: self.fdt,
                    });
                }
                FDT_END_NODE => {
                    self.depth = self.depth.checked_sub(1)?;
                }
                FDT_NOP => {}
                FDT_END => self.done = true,
                _ => return None,
            }
        }

        None
    }
}

fn skip_props(block: &[u8], offset: &mut usize) -> Option<usize> {
    let mut cursor = *offset;
    loop {
        let token = take_token(block, &mut cursor)?;
        match token {
            FDT_PROP => {
                let len = usize::try_from(take_token(block, &mut cursor)?).ok()?;
                let _nameoff = take_token(block, &mut cursor)?;
                cursor = align_up_4(cursor.checked_add(len)?)?;
            }
            FDT_NOP => {}
            _ => {
                let props_end = cursor.checked_sub(4)?;
                *offset = props_end;
                return Some(props_end);
            }
        }
    }
}

fn take_token(block: &[u8], offset: &mut usize) -> Option<u32> {
    let token = read_be_u32_at(block, *offset)?;
    *offset = offset.checked_add(4)?;
    Some(token)
}

fn read_be_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let raw = bytes.get(offset..end)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn cstr_at(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let tail = bytes.get(offset..)?;
    let len = tail.iter().position(|byte| *byte == 0)?;
    Some(&tail[..len])
}

const fn align_up_4(value: usize) -> Option<usize> {
    let value = match value.checked_add(3) {
        Some(value) => value,
        None => return None,
    };
    Some(value & !3)
}
