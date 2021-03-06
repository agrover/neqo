#![allow(unused_variables, dead_code)]

use std::collections::HashMap;

use super::test_stream::{get_stream_type, Stream};
use neqo_transport::connection::{Datagram, Role, State};
use neqo_transport::frame::StreamType;
use neqo_transport::{AppError, ConnectionError, Res};
use neqo_transport::{Recvable, Sendable};

pub struct Connection {
    rol: Role,
    st: State,
    deadline: u64,
    next_stream_id: u64,
    pub streams: HashMap<u64, Stream>,
}

pub struct Agent {}

impl Connection {
    fn new(r: Role) -> Connection {
        Connection {
            rol: r,
            st: State::Init,
            deadline: 0,
            next_stream_id: 0,
            streams: HashMap::new(),
        }
    }

    /// Get the current role.
    pub fn role(&self) -> Role {
        self.rol
    }

    pub fn new_client() -> Connection {
        Connection::new(Role::Client)
    }

    pub fn new_server() -> Connection {
        Connection::new(Role::Server)
    }

    pub fn process<I>(&mut self, _in_dgrams: I, cur_time: u64) -> (Vec<Datagram>, u64)
    where
        I: IntoIterator<Item = Datagram>,
    {
        self.st = State::Connected;
        (Vec::new(), 0)
    }

    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        let stream_id = self.next_stream_id;
        self.streams
            .insert(stream_id, Stream::new(get_stream_type(self.rol, st)));
        self.next_stream_id += 1;
        Ok(stream_id)
    }

    pub fn get_recvable_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Recvable)> + 'a> {
        Box::new(
            self.streams
                .iter_mut()
                .map(|(x, y)| (*x, y as &mut Recvable)),
        )
    }

    pub fn get_sendable_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Sendable)> + 'a> {
        Box::new(
            self.streams
                .iter_mut()
                .map(|(x, y)| (*x, y as &mut Sendable)),
        )
    }

    pub fn close_receive_side(&mut self, id: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.receive_close();
        }
    }

    pub fn stream_reset(&mut self, id: u64, err: AppError) -> Res<()> {
        if let Some(s) = self.streams.get_mut(&id) {
            s.reset(err);
        }
        Ok(())
    }

    pub fn close<S: Into<String>>(&mut self, err: AppError, _msg: S) {
        self.st = State::Closed(ConnectionError::Application(err));
    }

    pub fn state(&self) -> &State {
        &self.st
    }
}
