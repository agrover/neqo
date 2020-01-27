// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::huffman::encode_huffman;
use crate::qpack_helper::read_prefixed_encoded_int_with_connection;
use crate::qpack_send_buf::QPData;
use crate::table::{HeaderTable, LookupResult};
use crate::Header;
use crate::{Error, Res};
use neqo_common::{log::NeqoQlogRef, qdebug, qtrace};
use neqo_transport::Connection;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryInto;

pub const QPACK_UNI_STREAM_TYPE_ENCODER: u64 = 0x2;

#[derive(Debug)]
enum DecoderInstructions {
    InsertCountIncrement,
    HeaderAck,
    StreamCancellation,
}

fn get_instruction(b: u8) -> DecoderInstructions {
    if (b & 0xc0) == 0 {
        DecoderInstructions::InsertCountIncrement
    } else if (b & 0x80) != 0 {
        DecoderInstructions::HeaderAck
    } else {
        DecoderInstructions::StreamCancellation
    }
}

#[derive(Debug)]
pub struct QPackEncoder {
    table: HeaderTable,
    send_buf: QPData,
    max_entries: u64,
    instruction_reader_current_inst: Option<DecoderInstructions>,
    instruction_reader_value: u64, // this is instruction dependent value.
    instruction_reader_cnt: u8, // this is helper variable for reading a prefixed integer encoded value
    local_stream_id: Option<u64>,
    remote_stream_id: Option<u64>,
    max_blocked_streams: u16,
    // Remember header blocks that are referring to dynamic table.
    // There can be multiple header blocks in one stream, headers, trailer, push stream request, etc.
    // This HashMap maps a stream ID to a list of header blocks. Each header block is a list of
    // referenced dynamic table entries.
    unacked_header_blocks: HashMap<u64, VecDeque<HashSet<u64>>>,
    blocked_stream_cnt: u16,
    use_huffman: bool,
    log: Option<NeqoQlogRef>,
}

impl QPackEncoder {
    pub fn new(use_huffman: bool, log: Option<NeqoQlogRef>) -> Self {
        Self {
            table: HeaderTable::new(true),
            send_buf: QPData::default(),
            max_entries: 0,
            instruction_reader_current_inst: None,
            instruction_reader_value: 0,
            instruction_reader_cnt: 0,
            local_stream_id: None,
            remote_stream_id: None,
            max_blocked_streams: 0,
            unacked_header_blocks: HashMap::new(),
            blocked_stream_cnt: 0,
            use_huffman,
            log,
        }
    }

    pub fn set_max_capacity(&mut self, cap: u64) -> Res<()> {
        if cap > (1 << 30) - 1 {
            // TODO dragana check what is the correct error.
            return Err(Error::EncoderStreamError);
        }
        qdebug!([self], "Set max capacity to {}.", cap);
        self.max_entries = (cap as f64 / 32.0).floor() as u64;
        // we also set our table to the max allowed. TODO we may not want to use max allowed.
        self.change_capacity(cap)
    }

    pub fn set_max_blocked_streams(&mut self, blocked_streams: u64) -> Res<()> {
        self.max_blocked_streams = blocked_streams
            .try_into()
            .or(Err(Error::EncoderStreamError))?;
        Ok(())
    }

    pub fn recv_if_encoder_stream(&mut self, conn: &mut Connection, stream_id: u64) -> Res<bool> {
        match self.remote_stream_id {
            Some(id) => {
                if id == stream_id {
                    self.read_instructions(conn, stream_id)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            None => Ok(false),
        }
    }

    fn read_instructions(&mut self, conn: &mut Connection, stream_id: u64) -> Res<()> {
        qdebug!([self], "read a new instraction");
        loop {
            match self.instruction_reader_current_inst {
                None => {
                    // get new instruction
                    let mut b = [0];
                    match conn.stream_recv(stream_id, &mut b) {
                        Err(_) => break Err(Error::EncoderStreamError),
                        Ok((amount, fin)) => {
                            if fin {
                                break Err(Error::ClosedCriticalStream);
                            }
                            if amount != 1 {
                                // wait for more data.
                                break Ok(());
                            }
                        }
                    }
                    self.instruction_reader_current_inst = Some(get_instruction(b[0]));

                    // try to read data
                    let prefix_len = if (b[0] & 0x80) != 0 { 1 } else { 2 };
                    match read_prefixed_encoded_int_with_connection(
                        conn,
                        stream_id,
                        &mut self.instruction_reader_value,
                        &mut self.instruction_reader_cnt,
                        prefix_len,
                        b[0],
                        true,
                    ) {
                        Ok(done) => {
                            if done {
                                self.call_instruction()?;
                            } else {
                                // wait for more data.
                                break Ok(());
                            }
                        }
                        Err(Error::ClosedCriticalStream) => break Err(Error::ClosedCriticalStream),
                        Err(_) => break Err(Error::EncoderStreamError),
                    }
                }
                Some(_) => {
                    match read_prefixed_encoded_int_with_connection(
                        conn,
                        stream_id,
                        &mut self.instruction_reader_value,
                        &mut self.instruction_reader_cnt,
                        0,
                        0x0,
                        false,
                    ) {
                        Ok(done) => {
                            if done {
                                self.call_instruction()?;
                            } else {
                                // wait for more data.
                                break Ok(());
                            }
                        }
                        Err(Error::ClosedCriticalStream) => break Err(Error::ClosedCriticalStream),
                        Err(_) => break Err(Error::EncoderStreamError),
                    }
                }
            }
        }
    }

    fn recalculate_blocked_streams(&mut self) {
        let acked_inserts_cnt = self.table.get_acked_inserts_cnt();
        self.blocked_stream_cnt = 0;
        for (_, hb_list) in self.unacked_header_blocks.iter_mut() {
            debug_assert!(!hb_list.is_empty());
            if hb_list
                .iter()
                .flat_map(|hb| hb.iter())
                .any(|e| *e >= acked_inserts_cnt)
            {
                self.blocked_stream_cnt += 1;
            }
        }
    }

    fn insert_count_instruction(&mut self, increment: u64) -> Res<()> {
        self.table.increment_acked(increment)?;
        self.recalculate_blocked_streams();
        Ok(())
    }

    fn header_ack(&mut self, stream_id: u64) -> Res<()> {
        let mut new_acked = self.table.get_acked_inserts_cnt();
        if let Some(hb_list) = self.unacked_header_blocks.get_mut(&stream_id) {
            if let Some(ref_list) = hb_list.pop_back() {
                for iter in ref_list {
                    self.table.remove_ref(iter);
                    if iter >= new_acked {
                        new_acked = iter + 1;
                    }
                }
            } else {
                debug_assert!(false, "We should have at least one header block.");
            }
            if hb_list.is_empty() {
                self.unacked_header_blocks.remove(&stream_id);
            }
        }
        if new_acked > self.table.get_acked_inserts_cnt() {
            self.insert_count_instruction(new_acked - self.table.get_acked_inserts_cnt())
                .expect("This should neve happen");
        }
        Ok(())
    }

    fn stream_cancellation(&mut self, stream_id: u64) -> Res<()> {
        let mut was_blocker = false;
        if let Some(hb_list) = self.unacked_header_blocks.get_mut(&stream_id) {
            debug_assert!(!hb_list.is_empty());
            while let Some(ref_list) = hb_list.pop_front() {
                for iter in ref_list {
                    self.table.remove_ref(iter);
                    was_blocker = was_blocker || (iter >= self.table.get_acked_inserts_cnt());
                }
            }
        }
        if was_blocker {
            debug_assert!(self.blocked_stream_cnt > 0);
            self.blocked_stream_cnt -= 1;
        }
        Ok(())
    }

    fn call_instruction(&mut self) -> Res<()> {
        if let Some(inst) = &self.instruction_reader_current_inst {
            qdebug!([self], "call intruction {:?}", inst);
            match inst {
                DecoderInstructions::InsertCountIncrement => {
                    self.insert_count_instruction(self.instruction_reader_value)?
                }
                DecoderInstructions::HeaderAck => self.header_ack(self.instruction_reader_value)?,
                DecoderInstructions::StreamCancellation => {
                    self.stream_cancellation(self.instruction_reader_value)?
                }
            };
            self.instruction_reader_current_inst = None;
            self.instruction_reader_value = 0;
            self.instruction_reader_cnt = 0;
        } else {
            panic!("We must have a instruction decoded beforewe call call_instruction");
        }
        Ok(())
    }

    pub fn insert_with_name_ref(
        &mut self,
        name_static_table: bool,
        name_index: u64,
        value: &[u8],
    ) -> Res<()> {
        qdebug!(
            [self],
            "insert with name reference {} from {} value={:x?}.",
            name_index,
            if name_static_table {
                "static table"
            } else {
                "dynamic table"
            },
            value
        );
        self.table
            .insert_with_name_ref(name_static_table, name_index, value)?;

        // write instruction
        let instr = 0x80 | (if name_static_table { 0x40 } else { 0x00 });
        self.send_buf
            .encode_prefixed_encoded_int(instr, 2, name_index);
        encode_literal(self.use_huffman, &mut self.send_buf, 0x0, 0, value);
        Ok(())
    }

    pub fn insert_with_name_literal(&mut self, name: &[u8], value: &[u8]) -> Res<u64> {
        qdebug!([self], "insert name {:x?}, value={:x?}.", name, value);
        // try to insert a new entry
        let index = self.table.insert(name, value)?;

        // encode instruction.
        encode_literal(self.use_huffman, &mut self.send_buf, 0x40, 2, name);
        encode_literal(self.use_huffman, &mut self.send_buf, 0x0, 0, value);

        Ok(index)
    }

    pub fn duplicate(&mut self, index: u64) -> Res<()> {
        qdebug!([self], "duplicate entry {}.", index);
        self.table.duplicate(index)?;
        self.send_buf.encode_prefixed_encoded_int(0x00, 3, index);
        Ok(())
    }

    pub fn change_capacity(&mut self, cap: u64) -> Res<()> {
        qdebug!([self], "change capacity: {}", cap);
        self.table.set_capacity(cap)?;
        self.send_buf.encode_prefixed_encoded_int(0x20, 3, cap);
        Ok(())
    }

    pub fn send(&mut self, conn: &mut Connection) -> Res<()> {
        if self.send_buf.is_empty() {
            Ok(())
        } else if let Some(stream_id) = self.local_stream_id {
            match conn.stream_send(stream_id, &self.send_buf[..]) {
                Err(_) => Err(Error::EncoderStreamError),
                Ok(r) => {
                    qdebug!([self], "{} bytes sent.", r);
                    self.send_buf.read(r as usize);
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    fn is_stream_blocker(&self, stream_id: u64) -> bool {
        if let Some(hb_list) = self.unacked_header_blocks.get(&stream_id) {
            debug_assert!(!hb_list.is_empty());
            match hb_list.iter().flat_map(|hb| hb.iter()).max() {
                Some(max_ref) => *max_ref >= self.table.get_acked_inserts_cnt(),
                None => false,
            }
        } else {
            false
        }
    }

    pub fn encode_header_block(&mut self, h: &[Header], stream_id: u64) -> QPData {
        qdebug!([self], "encoding headers.");
        let mut encoded_h = QPData::default();
        let base = self.table.base();
        self.encode_header_block_prefix(&mut encoded_h, false, 0, base, true);

        let stream_is_blocker = self.is_stream_blocker(stream_id);
        let can_block = self.blocked_stream_cnt < self.max_blocked_streams || stream_is_blocker;

        let mut ref_entries = HashSet::new();

        for iter in h.iter() {
            let name = iter.0.clone().into_bytes();
            let value = iter.1.clone().into_bytes();
            qtrace!("encoding {:x?} {:x?}.", name, value);

            if let Some(LookupResult {
                index,
                static_table,
                value_matches,
            }) = self.table.lookup(&name, &value, can_block)
            {
                qtrace!(
                    [self],
                    "found a {} entry, value-match={}",
                    if static_table { "static" } else { "dynamic" },
                    value_matches
                );
                if static_table {
                    if value_matches {
                        self.encode_indexed(&mut encoded_h, true, index);
                    } else {
                        self.encode_literal_with_name_ref(&mut encoded_h, true, index, &value);
                    }
                } else {
                    if value_matches {
                        if index < base {
                            self.encode_indexed(&mut encoded_h, false, base - index - 1);
                        } else {
                            self.encode_post_base_index(&mut encoded_h, index - base);
                        }
                    } else if index < base {
                        self.encode_literal_with_name_ref(
                            &mut encoded_h,
                            false,
                            base - index - 1,
                            &value,
                        );
                    } else {
                        self.encode_literal_with_post_based_name_ref(
                            &mut encoded_h,
                            index - base,
                            &value,
                        );
                    }
                    ref_entries.insert(index);
                }
            } else if !can_block {
                self.encode_literal_with_name_literal(&mut encoded_h, &name, &value);
            } else {
                match self.insert_with_name_literal(&name, &value) {
                    Ok(index) => {
                        self.encode_post_base_index(&mut encoded_h, index - base);
                        ref_entries.insert(index);
                    }
                    Err(_) => {
                        self.encode_literal_with_name_literal(&mut encoded_h, &name, &value);
                    }
                }
            }
        }
        for iter in &ref_entries {
            self.table.add_ref(*iter);
        }

        if let Some(max_ref) = ref_entries.iter().max() {
            self.fix_header_block_prefix(&mut encoded_h, base, *max_ref + 1);
            // Check if it is already blocking
            if !stream_is_blocker && *max_ref >= self.table.get_acked_inserts_cnt() {
                debug_assert!(self.blocked_stream_cnt < self.max_blocked_streams);
                self.blocked_stream_cnt += 1;
            }
        }

        if !ref_entries.is_empty() {
            self.unacked_header_blocks
                .entry(stream_id)
                .or_insert_with(VecDeque::new)
                .push_front(ref_entries);
        }
        encoded_h
    }

    fn encode_header_block_prefix(
        &self,
        buf: &mut QPData,
        fix: bool,
        req_insert_cnt: u64,
        delta: u64,
        positive: bool,
    ) {
        qdebug!(
            [self],
            "encode header block prefix req_insert_cnt={} delta={} (fix={}).",
            req_insert_cnt,
            delta,
            fix
        );
        let enc_insert_cnt = if req_insert_cnt != 0 {
            (req_insert_cnt % (2 * self.max_entries)) + 1
        } else {
            0
        };

        let mut offset = 0; // this is for fixing header_block only.
        if !fix {
            buf.encode_prefixed_encoded_int(0x0, 0, enc_insert_cnt);
        } else {
            // TODO fix for case when there is no enough space!!!
            offset = buf.encode_prefixed_encoded_int_fix(0, 0x0, 0, enc_insert_cnt);
        }
        let prefix = if positive { 0x00 } else { 0x80 };
        if !fix {
            buf.encode_prefixed_encoded_int(prefix, 1, delta);
        } else {
            let _ = buf.encode_prefixed_encoded_int_fix(offset, prefix, 1, delta);
        }
    }

    fn fix_header_block_prefix(&self, buf: &mut QPData, base: u64, req_insert_cnt: u64) {
        if req_insert_cnt > 0 {
            if req_insert_cnt <= base {
                self.encode_header_block_prefix(
                    buf,
                    true,
                    req_insert_cnt,
                    base - req_insert_cnt,
                    true,
                );
            } else {
                self.encode_header_block_prefix(
                    buf,
                    true,
                    req_insert_cnt,
                    req_insert_cnt - base - 1,
                    false,
                );
            }
        }
    }

    fn encode_indexed(&self, buf: &mut QPData, is_static: bool, index: u64) {
        qdebug!([self], "encode index {} (static={}).", index, is_static);
        let prefix = if is_static { 0xc0 } else { 0x80 };
        buf.encode_prefixed_encoded_int(prefix, 2, index);
    }

    fn encode_literal_with_name_ref(
        &self,
        buf: &mut QPData,
        is_static: bool,
        index: u64,
        value: &[u8],
    ) {
        qdebug!(
            [self],
            "encode literal with name ref - index={}, static={}, value={:x?}",
            index,
            is_static,
            value
        );
        let prefix = if is_static { 0x50 } else { 0x40 };
        buf.encode_prefixed_encoded_int(prefix, 4, index);
        encode_literal(self.use_huffman, buf, 0x0, 0, value);
    }

    fn encode_post_base_index(&self, buf: &mut QPData, index: u64) {
        qdebug!([self], "encode post base index {}.", index);
        buf.encode_prefixed_encoded_int(0x10, 4, index);
    }

    fn encode_literal_with_post_based_name_ref(&self, buf: &mut QPData, index: u64, value: &[u8]) {
        qdebug!(
            [self],
            "encode literal with post base index - index={}, value={:x?}.",
            index,
            value
        );
        buf.encode_prefixed_encoded_int(0x00, 5, index);
        encode_literal(self.use_huffman, buf, 0x0, 0, value);
    }

    fn encode_literal_with_name_literal(&self, buf: &mut QPData, name: &[u8], value: &[u8]) {
        qdebug!(
            [self],
            "encode literal with name literal - name={:x?}, value={:x?}.",
            name,
            value
        );
        encode_literal(self.use_huffman, buf, 0x20, 4, name);
        encode_literal(self.use_huffman, buf, 0x0, 0, value);
    }

    pub fn add_send_stream(&mut self, stream_id: u64) {
        if self.local_stream_id.is_some() {
            panic!("Adding multiple local streams");
        }
        self.local_stream_id = Some(stream_id);
        self.send_buf
            .write_byte(QPACK_UNI_STREAM_TYPE_ENCODER as u8);
    }

    pub fn add_recv_stream(&mut self, stream_id: u64) -> Res<()> {
        match self.remote_stream_id {
            Some(_) => Err(Error::WrongStreamCount),
            None => {
                self.remote_stream_id = Some(stream_id);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub fn blocked_stream_cnt(&self) -> u16 {
        self.blocked_stream_cnt
    }
}

fn encode_literal(use_huffman: bool, buf: &mut QPData, prefix: u8, prefix_len: u8, value: &[u8]) {
    if use_huffman {
        let encoded = encode_huffman(value);
        buf.encode_prefixed_encoded_int(
            prefix | (0x80 >> prefix_len),
            prefix_len + 1,
            encoded.len() as u64,
        );
        buf.write_bytes(&encoded);
    } else {
        buf.encode_prefixed_encoded_int(prefix, prefix_len + 1, value.len() as u64);
        buf.write_bytes(&value);
    }
}

impl ::std::fmt::Display for QPackEncoder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "QPackEncoder")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_transport::StreamType;
    use test_fixture::*;

    struct TestEncoder {
        encoder: QPackEncoder,
        send_stream_id: u64,
        recv_stream_id: u64,
        conn: Connection,
        peer_conn: Connection,
    }

    fn connect(huffman: bool) -> TestEncoder {
        let (mut conn, mut peer_conn) = test_fixture::connect();

        // create a stream
        let recv_stream_id = peer_conn.stream_create(StreamType::UniDi).unwrap();
        let send_stream_id = conn.stream_create(StreamType::UniDi).unwrap();

        // create an encoder
        let mut encoder = QPackEncoder::new(huffman, None);
        encoder.add_send_stream(send_stream_id);

        TestEncoder {
            encoder,
            send_stream_id,
            recv_stream_id,
            conn,
            peer_conn,
        }
    }

    fn send_instructions(encoder: &mut TestEncoder, encoder_instruction: &[u8]) {
        encoder.encoder.send(&mut encoder.conn).unwrap();
        let out = encoder.conn.process(None, now());
        encoder.peer_conn.process(out.dgram(), now());
        let mut buf = [0u8; 100];
        let (amount, fin) = encoder
            .peer_conn
            .stream_recv(encoder.send_stream_id, &mut buf)
            .unwrap();
        assert_eq!(fin, false);
        assert_eq!(buf[..amount], encoder_instruction[..]);
    }

    fn recv_instruction(encoder: &mut TestEncoder, decoder_instruction: &[u8]) {
        encoder
            .peer_conn
            .stream_send(encoder.recv_stream_id, decoder_instruction)
            .unwrap();
        let out = encoder.peer_conn.process(None, now());
        encoder.conn.process(out.dgram(), now());
        assert!(encoder
            .encoder
            .read_instructions(&mut encoder.conn, encoder.recv_stream_id)
            .is_ok());
    }

    const CAP_INSTRUCTION_200: &[u8] = &[0x02, 0x3f, 0xa9, 0x01];
    const CAP_INSTRUCTION_60: &[u8] = &[0x02, 0x3f, 0x1d];

    const HEADER_CONTENT_LENGTH: &[u8] = &[
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
    ];
    const VALUE_1: &[u8] = &[0x31, 0x32, 0x33, 0x34];
    const VALUE_2: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35];

    // HEADER_CONTENT_LENGTH and VALUE_1 encoded by instruction insert_with_name_literal.
    const HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL: &[u8] = &[
        0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
        0x04, 0x31, 0x32, 0x33, 0x34,
    ];

    // HEADER_CONTENT_LENGTH and VALUE_2 encoded by instruction insert_with_name_literal.
    const HEADER_CONTENT_LENGTH_VALUE_2_NAME_LITERAL: &[u8] = &[
        0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
        0x05, 0x31, 0x32, 0x33, 0x34, 0x35,
    ];

    // Indexed Header Field that refers to the first entry in the dynamic table.
    const ENCODE_INDEXED_REF_DYNAMIC: &[u8] = &[0x02, 0x00, 0x80];

    const HEADER_ACK_STREAM_ID_1: &[u8] = &[0x81];
    const HEADER_ACK_STREAM_ID_2: &[u8] = &[0x82];
    const STREAM_CANCELED_ID_1: &[u8] = &[0x41];

    // test insert_with_name_ref which fails because there is not enough space in the table
    #[test]
    fn test_insert_with_name_ref_1() {
        let mut encoder = connect(false);
        let e = encoder
            .encoder
            .insert_with_name_ref(true, 4, VALUE_1)
            .unwrap_err();
        assert_eq!(Error::EncoderStreamError, e);
        send_instructions(&mut encoder, &[0x02]);
    }

    // test insert_name_ref that succeeds
    #[test]
    fn test_insert_with_name_ref_2() {
        let mut encoder = connect(false);
        assert!(encoder.encoder.set_max_capacity(200).is_ok());
        // test the change capacity instruction.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        assert!(encoder
            .encoder
            .insert_with_name_ref(true, 4, VALUE_1)
            .is_ok());
        send_instructions(&mut encoder, &[0xc4, 0x04, 0x31, 0x32, 0x33, 0x34]);
    }

    // test insert_with_name_literal which fails because there is not enough space in the table
    #[test]
    fn test_insert_with_name_literal_1() {
        let mut encoder = connect(false);

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);
        assert_eq!(Error::EncoderStreamError, res.unwrap_err());
        send_instructions(&mut encoder, &[0x02]);
    }

    // test insert_with_name_literal - succeeds
    #[test]
    fn test_insert_with_name_literal_2() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());
        // test the change capacity instruction.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);
        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);
    }

    #[test]
    fn test_change_capacity() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);
    }

    #[test]
    fn test_duplicate() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());
        // test the change capacity instruction.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);
        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        assert!(encoder.encoder.duplicate(0).is_ok());
        send_instructions(&mut encoder, &[0x00]);
    }

    struct TestElement {
        pub headers: Vec<Header>,
        pub header_block: &'static [u8],
        pub encoder_inst: &'static [u8],
    }

    #[test]
    fn test_header_block_encoder_non() {
        let test_cases: [TestElement; 6] = [
            // test a header with ref to static - encode_indexed
            TestElement {
                headers: vec![(String::from(":method"), String::from("GET"))],
                header_block: &[0x00, 0x00, 0xd1],
                encoder_inst: &[],
            },
            // test encode_literal_with_name_ref
            TestElement {
                headers: vec![(String::from(":path"), String::from("/somewhere"))],
                header_block: &[
                    0x00, 0x00, 0x51, 0x0a, 0x2f, 0x73, 0x6f, 0x6d, 0x65, 0x77, 0x68, 0x65, 0x72,
                    0x65,
                ],
                encoder_inst: &[],
            },
            // test adding a new header and encode_post_base_index, also test fix_header_block_prefix
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value"))],
                header_block: &[0x02, 0x80, 0x10],
                encoder_inst: &[
                    0x49, 0x6d, 0x79, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x08, 0x6d, 0x79,
                    0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
                ],
            },
            // test encode_indexed with a ref to dynamic table.
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value"))],
                header_block: ENCODE_INDEXED_REF_DYNAMIC,
                encoder_inst: &[],
            },
            // test encode_literal_with_name_ref.
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value2"))],
                header_block: &[
                    0x02, 0x00, 0x40, 0x09, 0x6d, 0x79, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32,
                ],
                encoder_inst: &[],
            },
            // test multiple headers
            TestElement {
                headers: vec![
                    (String::from(":method"), String::from("GET")),
                    (String::from(":path"), String::from("/somewhere")),
                    (String::from(":authority"), String::from("example.com")),
                    (String::from(":scheme"), String::from("https")),
                ],
                header_block: &[
                    0x00, 0x01, 0xd1, 0x51, 0x0a, 0x2f, 0x73, 0x6f, 0x6d, 0x65, 0x77, 0x68, 0x65,
                    0x72, 0x65, 0x50, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
                    0x6f, 0x6d, 0xd7,
                ],
                encoder_inst: &[],
            },
        ];

        let mut encoder = connect(false);

        encoder.encoder.set_max_blocked_streams(100).unwrap();
        encoder.encoder.set_max_capacity(200).unwrap();

        // test the change capacity instruction.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        for t in &test_cases {
            let buf = encoder.encoder.encode_header_block(&t.headers, 1);
            assert_eq!(&buf[..], t.header_block);
            send_instructions(&mut encoder, t.encoder_inst);
        }
    }

    #[test]
    fn test_header_block_encoder_huffman() {
        let test_cases: [TestElement; 6] = [
            // test a header with ref to static - encode_indexed
            TestElement {
                headers: vec![(String::from(":method"), String::from("GET"))],
                header_block: &[0x00, 0x00, 0xd1],
                encoder_inst: &[],
            },
            // test encode_literal_with_name_ref
            TestElement {
                headers: vec![(String::from(":path"), String::from("/somewhere"))],
                header_block: &[
                    0x00, 0x00, 0x51, 0x87, 0x61, 0x07, 0xa4, 0xbe, 0x27, 0x2d, 0x85,
                ],
                encoder_inst: &[],
            },
            // test adding a new header and encode_post_base_index, also test fix_header_block_prefix
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value"))],
                header_block: &[0x02, 0x80, 0x10],
                encoder_inst: &[
                    0x67, 0xa7, 0xd2, 0xd3, 0x94, 0x72, 0x16, 0xcf, 0x86, 0xa7, 0xd2, 0xdd, 0xc7,
                    0x45, 0xa5,
                ],
            },
            // test encode_indexed with a ref to dynamic table.
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value"))],
                header_block: ENCODE_INDEXED_REF_DYNAMIC,
                encoder_inst: &[],
            },
            // test encode_literal_with_name_ref.
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value2"))],
                header_block: &[
                    0x02, 0x00, 0x40, 0x87, 0xa7, 0xd2, 0xdd, 0xc7, 0x45, 0xa5, 0x17,
                ],
                encoder_inst: &[],
            },
            // test multiple headers
            TestElement {
                headers: vec![
                    (String::from(":method"), String::from("GET")),
                    (String::from(":path"), String::from("/somewhere")),
                    (String::from(":authority"), String::from("example.com")),
                    (String::from(":scheme"), String::from("https")),
                ],
                header_block: &[
                    0x00, 0x01, 0xd1, 0x51, 0x87, 0x61, 0x07, 0xa4, 0xbe, 0x27, 0x2d, 0x85, 0x50,
                    0x88, 0x2f, 0x91, 0xd3, 0x5d, 0x05, 0x5c, 0x87, 0xa7, 0xd7,
                ],
                encoder_inst: &[],
            },
        ];

        let mut encoder = connect(true);

        encoder.encoder.set_max_blocked_streams(100).unwrap();
        encoder.encoder.set_max_capacity(200).unwrap();

        // test the change capacity instruction.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        for t in &test_cases {
            let buf = encoder.encoder.encode_header_block(&t.headers, 1);
            assert_eq!(&buf[..], t.header_block);
            send_instructions(&mut encoder, t.encoder_inst);
        }
    }

    // Test inserts block on waiting for an insert count increment.
    #[test]
    fn test_insertion_blocked_on_insert_count_feedback() {
        let mut encoder = connect(false);

        encoder.encoder.set_max_capacity(60).unwrap();

        // test the change capacity instruction.
        send_instructions(&mut encoder, CAP_INSTRUCTION_60);

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);
        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        // insert "content-length: 12345 which will fail because the ntry in the table cannot be evicted.
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_2);
        assert!(res.is_err());
        send_instructions(&mut encoder, &[]);

        // receive an insert count increment.
        recv_instruction(&mut encoder, &[0x01]);

        // insert "content-length: 12345 again it will succeed.
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_2);
        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_2_NAME_LITERAL);
    }

    // Test inserts block on waiting for acks
    // test the table insertion is blocked:
    // 0 - waiting for a header ack
    // 2 - waiting for a stream cancel.
    fn test_insertion_blocked_on_waiting_for_header_ack_or_stream_cancel(wait: u8) {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(60).is_ok());
        // test the change capacity instruction.
        send_instructions(&mut encoder, CAP_INSTRUCTION_60);

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);
        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        // receive an insert count increment.
        recv_instruction(&mut encoder, &[0x01]);

        // send a header block
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("content-length"), String::from("1234"))], 1);
        assert_eq!(&buf[..], ENCODE_INDEXED_REF_DYNAMIC);
        send_instructions(&mut encoder, &[]);

        // insert "content-length: 12345 which will fail because the entry in the table cannot be evicted
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_2);
        assert!(res.is_err());
        send_instructions(&mut encoder, &[]);

        if wait == 0 {
            // receive a header_ack.
            recv_instruction(&mut encoder, HEADER_ACK_STREAM_ID_1);
        } else {
            // receive a stream canceled
            recv_instruction(&mut encoder, STREAM_CANCELED_ID_1);
        }

        // insert "content-length: 12345 again it will succeed.
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_2);
        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_2_NAME_LITERAL);
    }

    #[test]
    fn test_header_ack() {
        test_insertion_blocked_on_waiting_for_header_ack_or_stream_cancel(0);
    }

    #[test]
    fn test_stream_canceled() {
        test_insertion_blocked_on_waiting_for_header_ack_or_stream_cancel(1);
    }

    fn assert_is_index_to_dynamic(buf: &[u8]) {
        assert_eq!(buf[2] & 0xc0, 0x80);
    }

    fn assert_is_index_to_dynamic_post(buf: &[u8]) {
        assert_eq!(buf[2] & 0xf0, 0x10);
    }

    fn assert_is_index_to_static_name_only(buf: &[u8]) {
        assert_eq!(buf[2] & 0xf0, 0x50);
    }

    fn assert_is_literal_value_literal_name(buf: &[u8]) {
        assert_eq!(buf[2] & 0xf0, 0x20);
    }

    #[test]
    fn max_block_streams1() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(60).is_ok());

        // change capacity to 60.
        send_instructions(&mut encoder, CAP_INSTRUCTION_60);

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);

        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        encoder.encoder.set_max_blocked_streams(1).unwrap();

        // send a header block, it refers to unacked entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("content-length"), String::from("1234"))], 1);
        assert_is_index_to_dynamic(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        send_instructions(&mut encoder, &[]);

        // The next one will not use the dynamic entry because it is exceeding the max_blocked_streams
        // limit.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("content-length"), String::from("1234"))], 2);
        assert_is_index_to_static_name_only(&buf);

        send_instructions(&mut encoder, &[]);
        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // another header block to already blocked stream can still use the entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("content-length"), String::from("1234"))], 1);
        assert_is_index_to_dynamic(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);
    }

    #[test]
    fn max_block_streams2() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());

        // change capacity to 200.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);

        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        // insert "content-length: 12345
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_2);

        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_2_NAME_LITERAL);

        encoder.encoder.set_max_blocked_streams(1).unwrap();

        let stream_id = 1;
        // send a header block, it refers to unacked entry.
        let buf = encoder.encoder.encode_header_block(
            &[(String::from("content-length"), String::from("1234"))],
            stream_id,
        );
        assert_is_index_to_dynamic(&buf);

        // encode another header block for the same stream that will refer to the second entry
        // in the dynamic table.
        // This should work because the stream is already a blocked stream
        // send a header block, it refers to unacked entry.
        let buf = encoder.encoder.encode_header_block(
            &[(String::from("content-length"), String::from("12345"))],
            stream_id,
        );
        assert_is_index_to_dynamic(&buf);
    }

    #[test]
    fn max_block_streams3() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());

        // change capacity to 200.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        encoder.encoder.set_max_blocked_streams(1).unwrap();

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);

        // send a header block, that creates an new entry and refers to it.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // The next one will not create a new entry because the encoder is on max_blocked_streams limit.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name2"), String::from("value2"))], 2);
        assert_is_literal_value_literal_name(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // another header block to already blocked stream can still create a new entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name2"), String::from("value2"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);
    }

    #[test]
    fn max_block_streams4() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());

        // change capacity to 200.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        encoder.encoder.set_max_blocked_streams(1).unwrap();

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);

        // send a header block, that creates an new entry and refers to it.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // another header block to already blocked stream can still create a new entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name2"), String::from("value2"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // receive a header_ack for the first header block.
        recv_instruction(&mut encoder, HEADER_ACK_STREAM_ID_1);

        // The stream is still blocking because the second header block is not acked.
        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);
    }

    #[test]
    fn max_block_streams5() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());

        // change capacity to 200.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        encoder.encoder.set_max_blocked_streams(1).unwrap();

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);

        // send a header block, that creates an new entry and refers to it.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // another header block to already blocked stream can still create a new entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 1);
        assert_is_index_to_dynamic(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // receive a header_ack for the first header block.
        recv_instruction(&mut encoder, HEADER_ACK_STREAM_ID_1);

        // The stream is not blocking anymore because header ack also acks the instruction.
        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);
    }

    #[test]
    fn max_block_streams6() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());

        // change capacity to 200.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        encoder.encoder.set_max_blocked_streams(2).unwrap();

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);

        // send a header block, that creates an new entry and refers to it.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // header block for the next stream will create an new entry as well.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name2"), String::from("value2"))], 2);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 2);

        // receive a header_ack for the second header block. This will ack the first as well
        recv_instruction(&mut encoder, HEADER_ACK_STREAM_ID_2);

        // The stream is not blocking anymore because header ack also acks the instruction.
        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);
    }

    #[test]
    fn max_block_streams7() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());

        // change capacity to 200.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        encoder.encoder.set_max_blocked_streams(2).unwrap();

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);

        // send a header block, that creates an new entry and refers to it.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // header block for the next stream will create an new entry as well.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 2);
        assert_is_index_to_dynamic(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 2);

        // receive a stream cancel for the first stream.
        // This will remove the first stream as blocking but it will not mark the instruction as acked.
        // and the second steam will still be blocking.
        recv_instruction(&mut encoder, STREAM_CANCELED_ID_1);

        // The stream is not blocking anymore because header ack also acks the instruction.
        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);
    }

    #[test]
    fn max_block_stream8() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(200).is_ok());

        // change capacity to 200.
        send_instructions(&mut encoder, CAP_INSTRUCTION_200);

        encoder.encoder.set_max_blocked_streams(2).unwrap();

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 0);

        // send a header block, that creates an new entry and refers to it.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);

        // header block for the next stream will refer to the same entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name1"), String::from("value1"))], 2);
        assert_is_index_to_dynamic(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 2);

        // send another header block on stream 1.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("name2"), String::from("value2"))], 1);
        assert_is_index_to_dynamic_post(&buf);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 2);

        // stream 1 is block on entries 1 and 2; stream 2 is block only on 1.
        // receive an Insert Count Increment for the first entry.
        // After that only stream 1 will be blocking.
        recv_instruction(&mut encoder, &[0x01]);

        assert_eq!(encoder.encoder.blocked_stream_cnt(), 1);
    }

    #[test]
    fn dynamic_table_can_evict1() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(60).is_ok());

        // change capacity to 60.
        send_instructions(&mut encoder, CAP_INSTRUCTION_60);

        encoder.encoder.set_max_blocked_streams(2).unwrap();

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);

        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        // send a header block, it refers to unacked entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("content-length"), String::from("1234"))], 1);
        assert_is_index_to_dynamic(&buf);

        // trying to evict the entry will failed.
        assert!(encoder.encoder.set_max_capacity(10).is_err());

        // receive an Insert Count Increment for the entry.
        recv_instruction(&mut encoder, &[0x01]);

        // trying to evict the entry will failed. The stream is still referring to it.
        assert!(encoder.encoder.set_max_capacity(10).is_err());

        // receive a header_ack for the header block.
        recv_instruction(&mut encoder, HEADER_ACK_STREAM_ID_1);

        // now entry can be evicted.
        assert!(encoder.encoder.set_max_capacity(10).is_ok());
    }

    #[test]
    fn dynamic_table_can_evict2() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(60).is_ok());

        // change capacity to 60.
        send_instructions(&mut encoder, CAP_INSTRUCTION_60);

        encoder.encoder.set_max_blocked_streams(2).unwrap();

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);

        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        // send a header block, it refers to unacked entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("content-length"), String::from("1234"))], 1);
        assert_is_index_to_dynamic(&buf);

        // trying to evict the entry will failed.
        assert!(encoder.encoder.set_max_capacity(10).is_err());

        // receive an Insert Count Increment for the entry.
        recv_instruction(&mut encoder, &[0x01]);

        // trying to evict the entry will failed. The stream is still referring to it.
        assert!(encoder.encoder.set_max_capacity(10).is_err());

        // receive a stream cancelled.
        recv_instruction(&mut encoder, STREAM_CANCELED_ID_1);

        // now entry can be evicted.
        assert!(encoder.encoder.set_max_capacity(10).is_ok());
    }

    #[test]
    fn dynamic_table_can_evict3() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(60).is_ok());

        // change capacity to 60.
        send_instructions(&mut encoder, CAP_INSTRUCTION_60);

        encoder.encoder.set_max_blocked_streams(2).unwrap();

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);

        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        // trying to evict the entry will failed, because the entry is not acked.
        assert!(encoder.encoder.set_max_capacity(10).is_err());

        // receive an Insert Count Increment for the entry.
        recv_instruction(&mut encoder, &[0x01]);

        // now entry can be evicted.
        assert!(encoder.encoder.set_max_capacity(10).is_ok());
    }

    #[test]
    fn dynamic_table_can_evict4() {
        let mut encoder = connect(false);

        assert!(encoder.encoder.set_max_capacity(60).is_ok());

        // change capacity to 60.
        send_instructions(&mut encoder, CAP_INSTRUCTION_60);

        encoder.encoder.set_max_blocked_streams(2).unwrap();

        // insert "content-length: 1234
        let res = encoder
            .encoder
            .insert_with_name_literal(HEADER_CONTENT_LENGTH, VALUE_1);

        assert!(res.is_ok());
        send_instructions(&mut encoder, HEADER_CONTENT_LENGTH_VALUE_1_NAME_LITERAL);

        // send a header block, it refers to unacked entry.
        let buf = encoder
            .encoder
            .encode_header_block(&[(String::from("content-length"), String::from("1234"))], 1);
        assert_is_index_to_dynamic(&buf);

        // trying to evict the entry will failed. The stream is still referring to it and
        // entry is not acked.
        assert!(encoder.encoder.set_max_capacity(10).is_err());

        // receive a header_ack for the header block. This will also ack the instruction.
        recv_instruction(&mut encoder, HEADER_ACK_STREAM_ID_1);

        // now entry can be evicted.
        assert!(encoder.encoder.set_max_capacity(10).is_ok());
    }
}
