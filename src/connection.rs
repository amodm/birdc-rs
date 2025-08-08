//! Module that deals with connection and protocol related logic.
//!
//! Refer to documentation of [Connection] for more details.

use std::{
    collections::VecDeque,
    io::{ErrorKind, Read, Write},
    path::Path,
};

use crate::{
    Error, Interface, InterfaceAddress, InterfaceProperties, InterfaceSummary, Message, Protocol,
    ProtocolDetail, Result, ShowInterfacesMessage, ShowProtocolDetailsMessage, ShowStatusMessage,
};

/// An active connection, on which requests can be executed, and responses
/// received.
///
/// The request/response mechanism is serial, so if a request is made
/// before the response from the previous one has been fully received, you'll
/// get a [Error::OperationInProgress] error.
pub struct Connection {
    stream: tokio::net::UnixStream,
    unparsed_bytes: Vec<u8>,
    unsent_messages: VecDeque<Message>,
    request_in_progress: bool,
}

impl Connection {
    /// Open a new connection to this `unix_socket`, and consumes the
    /// introductory welcome message before returning the [Connection]
    pub(crate) async fn new<P: AsRef<Path>>(unix_socket: P) -> Result<Self> {
        // connect to the unix socket
        let stream = tokio::net::UnixStream::connect(unix_socket).await?;

        let mut connection = Connection {
            stream,
            unparsed_bytes: Vec::with_capacity(2 * READ_FRAME_SIZE),
            unsent_messages: VecDeque::with_capacity(20),
            // we mark this true because of the initial greeting
            request_in_progress: true,
        };

        // process greeting and return
        if let Message::Welcome(ref greeting) = connection.next_message().await? {
            log::trace!("received greeting {greeting}");
            // we need to do this because the message processor automatically adds an Ok
            if let Message::Ok = connection.next_message().await? {
                log::trace!("handshake completed. connection active");
                connection.allow_new_requests();
                return Ok(connection);
            }
        }
        Err(Error::InvalidToken("did not find greeting".into()))
    }

    /// Mark current request/response session as completed, so that new requests can
    /// be made on this connection.
    #[inline]
    fn allow_new_requests(&mut self) {
        self.request_in_progress = false;
    }

    /// Sends a request to the server and gets a vec of response messages. The
    /// terminating [Message::Ok] is not included.
    pub async fn send_request(&mut self, request: &str) -> Result<Vec<Message>> {
        // if there's already a request in progress, we shouldn't be sending
        // another request as we won't be able to differentiate the response
        if self.request_in_progress {
            return Err(Error::OperationInProgress);
        }

        // make sure we've cleared pending bytes & messages
        self.unparsed_bytes.clear();
        self.unsent_messages.clear();

        // send the request
        let request = if request.ends_with('\n') {
            request.to_owned()
        } else {
            format!("{}\n", &request)
        };
        let mut result: Vec<Message> = Vec::new();
        self.write_to_server(&request).await?;
        self.request_in_progress = true; // mark as operation in progress

        // receive all response messages
        loop {
            let message = self.next_message().await?;
            if let Message::Ok = message {
                self.allow_new_requests();
                return Ok(result);
            } else {
                result.push(message);
            }
        }
    }

    /// Sends a `show interfaces summary` request and returns the parsed response as a
    /// list of [InterfaceSummary] entries, one each for an interface.
    pub async fn show_interfaces_summary(&mut self) -> Result<Vec<InterfaceSummary>> {
        let messages = self.send_request("show interfaces summary").await?;

        // we ignore the 2005 message, and focus only on 1005
        for message in &messages {
            // if we get a 1005, we process it and return it
            if let Message::InterfaceSummary(_) = message {
                return if let Some(ifcs) = InterfaceSummary::from_enum(message) {
                    Ok(ifcs)
                } else {
                    Err(Error::ParseError(messages))
                };
            }
        }

        // if we didn't encounter any 1005, we return a ParseError
        Err(Error::ParseError(messages))
    }

    /// Sends a `show interfaces` request and returns the parsed response as a
    /// list of [ShowInterfacesMessage] entries, one each for an interface.
    pub async fn show_interfaces(&mut self) -> Result<Vec<ShowInterfacesMessage>> {
        let messages = self.send_request("show interfaces").await?;
        handle_show_interfaces(messages)
    }

    /// Sends a `show protocols [<pattern>]` request and returns the parsed response as a
    /// list of [InterfaceSummary] entries, one for each protocol.
    ///
    /// If `pattern` is specified, results of only those protocols is returned, which
    /// match the pattern.
    pub async fn show_protocols(&mut self, pattern: Option<&str>) -> Result<Vec<Protocol>> {
        let cmd = if let Some(pattern) = pattern {
            format!("show protocols \"{pattern}\"")
        } else {
            "show protocols".into()
        };
        let messages = self.send_request(&cmd).await?;
        handle_show_protocols(messages)
    }

    /// Sends a `show protocols all [<pattern>]` request and returns the parsed response as a
    /// list of [ShowProtocolDetailsMessage] entries, one for each protocol instance.
    ///
    /// If `pattern` is specified, results of only those protocols is returned, which
    /// match the pattern.
    pub async fn show_protocols_details(
        &mut self,
        pattern: Option<&str>,
    ) -> Result<Vec<ShowProtocolDetailsMessage>> {
        let cmd = if let Some(pattern) = pattern {
            format!("show protocols all \"{pattern}\"")
        } else {
            "show protocols all".into()
        };
        let messages = self.send_request(&cmd).await?;
        handle_show_protocols_details(messages)
    }

    /// Sends a `show status` request, and returns a semantically parsed response
    /// in the form of [ShowStatusMessage]
    pub async fn show_status(&mut self) -> Result<ShowStatusMessage> {
        let messages = self.send_request("show status").await?;

        match ShowStatusMessage::from_messages(&messages) {
            Some(ssm) => Ok(ssm),
            None => Err(Error::ParseError(messages)),
        }
    }

    /// Reads a full [Message] from the server, and returns it
    async fn next_message(&mut self) -> Result<Message> {
        // if we have pending messages, return the first one
        if let Some(pending_message) = self.unsent_messages.pop_front() {
            return Ok(pending_message);
        }

        // we are here because we don't have sufficient data in unparsed_bytes
        // to create a new message, so we have to fetch more
        self.fetch_new_messages().await?;
        if let Some(new_message) = self.unsent_messages.pop_front() {
            Ok(new_message)
        } else {
            // if we didn't get any message, there's something wrong
            Err(Error::eof("was expecting more messages"))
        }
    }

    /// Writes `request` to the server, returning only after it has been written
    /// fully.
    async fn write_to_server(&self, request: &str) -> Result<()> {
        let data = request.as_bytes();
        let total_size = data.len();
        let mut written_size = 0;
        loop {
            self.stream.writable().await?;
            match self.stream.try_write(data) {
                Ok(n) => {
                    written_size += n;
                    if written_size >= total_size {
                        return Ok(());
                    }
                }
                Err(err) => {
                    if err.kind() != ErrorKind::WouldBlock {
                        return Err(Error::from(err));
                    }
                }
            }
        }
    }

    /// Fetches and add news messages to the queue.
    #[inline]
    async fn fetch_new_messages(&mut self) -> Result<()> {
        loop {
            self.stream.readable().await?;
            let mut frame = [0_u8; READ_FRAME_SIZE];
            match self.stream.try_read(&mut frame) {
                Ok(0) => {
                    return Err(Error::eof("premature EOF"));
                }
                Ok(count) => {
                    if enqueue_messages(
                        &frame[..count],
                        &mut self.unparsed_bytes,
                        &mut self.unsent_messages,
                    )? == 0
                    {
                        // we continue to fetch more if amount of data
                        // was insufficient to parse response
                        continue;
                    } else {
                        return Ok(());
                    }
                }
                Err(err) => {
                    if err.kind() != ErrorKind::WouldBlock {
                        return Err(Error::IoError(err));
                    }
                }
            }
        }
    }
}

/// A non-async version of [Connection]
pub struct SyncConnection {
    stream: std::os::unix::net::UnixStream,
    unparsed_bytes: Vec<u8>,
    unsent_messages: VecDeque<Message>,
    request_in_progress: bool,
}

impl SyncConnection {
    /// Open a new connection to this `unix_socket`, and consumes the
    /// introductory welcome message before returning the [Connection]
    pub(crate) fn new<P: AsRef<Path>>(unix_socket: P) -> Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(unix_socket)?;

        let mut connection = SyncConnection {
            stream,
            unparsed_bytes: Vec::with_capacity(2 * READ_FRAME_SIZE),
            unsent_messages: VecDeque::with_capacity(20),
            request_in_progress: true,
        };

        if let Message::Welcome(ref greeting) = connection.next_message()? {
            log::trace!("received greeting {greeting}");
            if let Message::Ok = connection.next_message()? {
                log::trace!("handshake completed. connection active");
                connection.allow_new_requests();
                return Ok(connection);
            }
        }
        Err(Error::InvalidToken("did not find greeting".into()))
    }

    /// Mark current request/response session as completed, so that new requests can
    /// be made on this connection.
    #[inline]
    fn allow_new_requests(&mut self) {
        self.request_in_progress = false;
    }

    /// Sends a request to the server and gets a vec of response messages. The
    /// terminating [Message::Ok] is not included.
    pub fn send_request(&mut self, request: &str) -> Result<Vec<Message>> {
        if self.request_in_progress {
            return Err(Error::OperationInProgress);
        }

        self.unparsed_bytes.clear();
        self.unsent_messages.clear();

        let request = if request.ends_with('\n') {
            request.to_owned()
        } else {
            format!("{}\n", &request)
        };
        let mut result: Vec<Message> = Vec::new();
        self.write_to_server(&request)?;
        self.request_in_progress = true;

        loop {
            let message = self.next_message()?;
            if let Message::Ok = message {
                self.allow_new_requests();
                return Ok(result);
            } else {
                result.push(message);
            }
        }
    }

    /// Sends a `show interfaces summary` request and returns the parsed response as a
    /// list of [InterfaceSummary] entries, one each for an interface.
    pub fn show_interfaces_summary(&mut self) -> Result<Vec<InterfaceSummary>> {
        let messages = self.send_request("show interfaces summary")?;

        for message in &messages {
            if let Message::InterfaceSummary(_) = message {
                return if let Some(ifcs) = InterfaceSummary::from_enum(message) {
                    Ok(ifcs)
                } else {
                    Err(Error::ParseError(messages))
                };
            }
        }

        Err(Error::ParseError(messages))
    }

    /// Sends a `show interfaces` request and returns the parsed response as a
    /// list of [ShowInterfacesMessage] entries, one each for an interface.
    pub fn show_interfaces(&mut self) -> Result<Vec<ShowInterfacesMessage>> {
        let messages = self.send_request("show interfaces")?;
        handle_show_interfaces(messages)
    }

    /// Sends a `show protocols [<pattern>]` request and returns the parsed response as a
    /// list of [InterfaceSummary] entries, one for each protocol.
    ///
    /// If `pattern` is specified, results of only those protocols is returned, which
    /// match the pattern.
    pub fn show_protocols(&mut self, pattern: Option<&str>) -> Result<Vec<Protocol>> {
        let cmd = if let Some(pattern) = pattern {
            format!("show protocols \"{pattern}\"")
        } else {
            "show protocols".into()
        };
        let messages = self.send_request(&cmd)?;
        handle_show_protocols(messages)
    }

    /// Sends a `show protocols all [<pattern>]` request and returns the parsed response as a
    /// list of [ShowProtocolDetailsMessage] entries, one for each protocol instance.
    ///
    /// If `pattern` is specified, results of only those protocols is returned, which
    /// match the pattern.
    pub fn show_protocols_details(
        &mut self,
        pattern: Option<&str>,
    ) -> Result<Vec<ShowProtocolDetailsMessage>> {
        let cmd = if let Some(pattern) = pattern {
            format!("show protocols all \"{pattern}\"")
        } else {
            "show protocols all".into()
        };
        let messages = self.send_request(&cmd)?;
        handle_show_protocols_details(messages)
    }

    /// Sends a `show status` request, and returns a semantically parsed response
    /// in the form of [ShowStatusMessage]
    pub fn show_status(&mut self) -> Result<ShowStatusMessage> {
        let messages = self.send_request("show status")?;

        match ShowStatusMessage::from_messages(&messages) {
            Some(ssm) => Ok(ssm),
            None => Err(Error::ParseError(messages)),
        }
    }

    /// Reads a full [Message] from the server, and returns it
    fn next_message(&mut self) -> Result<Message> {
        if let Some(pending_message) = self.unsent_messages.pop_front() {
            return Ok(pending_message);
        }

        self.fetch_new_messages()?;
        if let Some(new_message) = self.unsent_messages.pop_front() {
            Ok(new_message)
        } else {
            Err(Error::eof("was expecting more messages"))
        }
    }

    /// Writes `request` to the server, returning only after it has been written
    /// fully.
    fn write_to_server(&mut self, request: &str) -> Result<()> {
        let data = request.as_bytes();
        let total_size = data.len();
        let mut written_size = 0;
        loop {
            match self.stream.write(data) {
                Ok(n) => {
                    written_size += n;
                    if written_size >= total_size {
                        return Ok(());
                    }
                }
                Err(err) => {
                    if err.kind() != ErrorKind::WouldBlock {
                        return Err(Error::from(err));
                    }
                }
            }
        }
    }

    /// Fetches and add news messages to the queue.
    #[inline]
    fn fetch_new_messages(&mut self) -> Result<()> {
        loop {
            let mut frame = [0_u8; READ_FRAME_SIZE];
            match self.stream.read(&mut frame) {
                Ok(0) => {
                    return Err(Error::eof("premature EOF"));
                }
                Ok(count) => {
                    if enqueue_messages(
                        &frame[..count],
                        &mut self.unparsed_bytes,
                        &mut self.unsent_messages,
                    )? == 0
                    {
                        continue;
                    } else {
                        return Ok(());
                    }
                }
                Err(err) => {
                    if err.kind() != ErrorKind::WouldBlock {
                        return Err(Error::IoError(err));
                    }
                }
            }
        }
    }
}

fn handle_show_interfaces(messages: Vec<Message>) -> Result<Vec<ShowInterfacesMessage>> {
    let mut result = vec![];

    // we expect messages to show up as a series of triplets: 1001, 1004 and 1003
    let mut idx = 0;
    loop {
        // each iteration here means fully going through all of 1001, 1004 and 1003

        // if we're already at end, return
        if idx >= messages.len() {
            return Ok(result);
        }

        // start processing
        let first_msg = &messages[idx];
        idx += 1;

        // process only if we find the first entry to be a 1001
        if let Some(msg_1001) = Interface::from_enum(first_msg) {
            // get the position of the next 1001
            let next_1001_idx = messages[idx..]
                .iter()
                .position(|x| matches!(x, Message::InterfaceList(_)))
                .unwrap_or(messages.len() - idx)
                + idx;
            let delta = next_1001_idx - idx;
            if delta == 0 || delta > 2 {
                log::error!(
                    "conn: parse failed: a 1001 entry without (or more than one) 1003/1004",
                );
                return Err(Error::ParseError(messages));
            }
            let mut msg_1004: Option<InterfaceProperties> = None;
            let mut msg_1003: Option<Vec<InterfaceAddress>> = None;
            while idx < next_1001_idx {
                let cur_msg = &messages[idx];
                idx += 1;
                match cur_msg {
                    Message::InterfaceFlags(_) => {
                        if let Some(props) = InterfaceProperties::from_enum(cur_msg) {
                            msg_1004 = Some(props);
                        } else {
                            return Err(Error::ParseError(messages));
                        }
                    }
                    Message::InterfaceAddress(_) => {
                        if let Some(addrs) = InterfaceAddress::from_enum(cur_msg) {
                            msg_1003 = Some(addrs);
                        } else {
                            return Err(Error::ParseError(messages));
                        }
                    }
                    _ => {
                        log::error!(
                            "conn: parse failed: found invalid code {}",
                            messages[idx].code()
                        );
                        return Err(Error::ParseError(messages));
                    }
                }
            }
            if let Some(msg_1004) = msg_1004 {
                result.push(ShowInterfacesMessage {
                    interface: msg_1001,
                    properties: msg_1004,
                    addresses: msg_1003.unwrap_or_default(),
                });
            } else {
                log::error!("conn: parse failed: found a 1001 without a 1004");
                return Err(Error::ParseError(messages));
            }
        } else {
            return Err(Error::ParseError(messages));
        }
    }
}

fn handle_show_protocols(messages: Vec<Message>) -> Result<Vec<Protocol>> {
    // we ignore the 2002 message, and focus only on 1005
    for message in &messages {
        // if we get a 1002, we process it and return it
        if let Message::ProtocolList(_) = message {
            return if let Some(protocols) = Protocol::from_enum(message) {
                Ok(protocols)
            } else {
                Err(Error::ParseError(messages))
            };
        }
    }

    // if we didn't encounter any 1002, we return a ParseError
    Err(Error::ParseError(messages))
}

fn handle_show_protocols_details(
    messages: Vec<Message>,
) -> Result<Vec<ShowProtocolDetailsMessage>> {
    let mut result = vec![];
    // we expect messages to show up as a series of doublets: 1002 and 1006
    if let Some(mut idx) = messages
        .iter()
        .position(|x| matches!(x, Message::ProtocolList(_)))
    {
        while idx < messages.len() {
            // each iteration here means fully going through the pair of 1002 and 1006

            if let Some(protocol) = Protocol::from_enum(&messages[idx]) {
                // move index to the next message
                idx += 1;
                // if we have a valid 1002 ...
                if let Some(protocol) = protocol.first() {
                    // ... check for 1006
                    if idx == messages.len()
                        || !matches!(messages[idx], Message::ProtocolDetails(_))
                    {
                        // if we're already at the end, or if there's no 1006 after the 1002 we saw
                        // just a step before, we push the current 1002 without any 1006, and continue
                        result.push(ShowProtocolDetailsMessage {
                            protocol: protocol.clone(),
                            detail: None,
                        });
                        continue;
                    }
                    // looks like we have a valid 1006, so let's process it
                    if let Some(detail) = ProtocolDetail::from_enum(&messages[idx]) {
                        // looks like we got a valid 1006
                        idx += 1;
                        result.push(ShowProtocolDetailsMessage {
                            protocol: protocol.clone(),
                            detail: Some(detail),
                        });
                    } else {
                        log::error!("conn: failed to parse 1006 message");
                        return Err(Error::ParseError(messages));
                    }
                }
            } else {
                log::error!("conn: failed to parse 1002 message: {:?}", messages[idx]);
                return Err(Error::ParseError(messages));
            }
        }

        Ok(result)
    } else {
        // No 1002 entries, so empty result
        Ok(Vec::new())
    }
}

/// Process raw bytes to parse and enqueue messages. On success returns the
/// number of messages enqueued.
///
/// If we have pending unparsed bytes from previous iterations, we create a
/// new buffer that combines the old one with the new `frame`, and then
/// processes it.
///
/// However, if we don't have any pending unparsed bytes, then it would be
/// an overhead to do so, so we just process the frame directly.
///
/// In both cases, pending bytes from this iteration are added to
/// `unparsed_bytes`
#[inline]
fn enqueue_messages(
    frame: &[u8],
    unparsed_bytes: &mut Vec<u8>,
    unsent_messages: &mut VecDeque<Message>,
) -> Result<usize> {
    let num_unparsed = unparsed_bytes.len();
    let has_unparsed = num_unparsed > 0;
    if has_unparsed {
        // if we had previously unparsed bytes, we use them in combination with
        // the new frame
        let mut new_vec: Vec<u8> = Vec::with_capacity(num_unparsed + frame.len());
        new_vec.extend_from_slice(unparsed_bytes);
        new_vec.extend_from_slice(frame);
        enqueue_messages_from_buffer(&new_vec, unparsed_bytes, unsent_messages)
    } else {
        // if we didn't have any previously unparsed bytes, we can process this
        // frame directly, gaining a tiny bit of efficiency. This helps in dealing
        // with most messages that will tend to be quite small.
        enqueue_messages_from_buffer(frame, unparsed_bytes, unsent_messages)
    }
}

/// Processes raw data to parse and enqeueue Messages.
///
/// The logic is straighforward, even if cumbersome to look at. We run a loop, where
/// at each iteration, we process a new line. In each line, we encounter one of the
/// following scenarios (xxxx is a 4 digit code):
/// 1. `xxxx<space><content>` - this is the last line in this response
/// 2. `xxxx<minus><content>` - this is NOT the last line in this response
/// 3. `<space><content>` - same as (2) but the xxxx code is implicitly = previous one
///
/// More details about the protocol can be found [here](https://gitlab.nic.cz/labs/bird/-/blob/master/nest/cli.c)
///
/// While processing each line, we can return an `Ok(0)` to indicate we need more
/// data ([Connection::fetch_new_messages] takes care of that).
#[inline]
fn enqueue_messages_from_buffer(
    buffer: &[u8],
    unparsed_bytes: &mut Vec<u8>,
    unsent_messages: &mut VecDeque<Message>,
) -> Result<usize> {
    let bsize = buffer.len();
    let mut num_messages = 0;
    let mut pos: usize = 0;
    let mut code: u32 = 0;
    let mut msg_start_pos = 0;
    let mut message_size: usize = 0;
    let mut last_msg_added_epos = 0;

    // process things line by line. each iteration of this loop constitutes
    // a new line
    loop {
        let line_start_pos = pos;
        log::trace!("conn: checking if we can start processing a new line");
        // break or ask for more data if we're at the end, but expected to parse
        if pos >= bsize {
            if num_messages > 0 {
                log::trace!(
                    "  need more data, exiting loop as already enqueued {num_messages} messages"
                );
                break;
            } else {
                log::trace!("  need more data");
                return Ok(0); // we need more data
            }
        }

        // if we don't have visibility into the next newline, break or ask
        // for more data
        let nl_pos: usize;
        match buffer[pos..].iter().position(|it| *it == b'\n') {
            Some(it) => nl_pos = pos + it,
            None => {
                if num_messages > 0 {
                    log::trace!(
                        "  need more data, exiting loop as already enqueued {num_messages} messages"
                    );
                    break;
                } else {
                    log::trace!("  need more data");
                    return Ok(0); // we need more data
                }
            }
        };
        let next_line_pos = nl_pos + 1;

        log::trace!(
            "conn: processing line: {}",
            String::from_utf8_lossy(&buffer[pos..nl_pos])
        );

        if buffer[pos] == b' ' {
            log::trace!("  no code present, we're a continuation of prev line");
            pos += 1; // we're now at start of data in this line
            message_size += nl_pos - pos + 1; // +1 for newline
        } else {
            log::trace!("  line has a code, need to check if same as prev or not");
            // the line does not start with a space, so we MUST see a code
            // and a continuation/final marker
            if pos + 5 >= bsize {
                if num_messages > 0 {
                    log::trace!(
                        "  need more data, exiting loop as already enqueued {num_messages} messages"
                    );
                    break;
                } else {
                    log::trace!("  need more data");
                    return Ok(0);
                }
            }
            let new_code = parse_code(&buffer[pos..(pos + 4)])?;
            let separator = buffer[pos + 4];
            log::trace!(
                "  encountered code {} and separator '{}'",
                new_code,
                separator as char
            );
            let is_last = match separator {
                b' ' => true,
                b'-' => false,
                _ => {
                    return Err(Error::InvalidToken(format!(
                        "unknown separator {separator} after code {new_code}"
                    )));
                }
            };
            pos += 5; // we're now at the start of data in this line

            let mut ok_added = false;
            if is_last {
                // if this is the last line
                if new_code == code {
                    log::trace!(
                        "  determined to be the last line, but has same code as before {code}"
                    );
                    // treat it as continuation of the previous message
                    message_size += nl_pos - pos + 1;
                    let message = parse_message(code, buffer, msg_start_pos, message_size)?;
                    log::trace!("  pushing last message {message:?}");
                    unsent_messages.push_back(message);
                    num_messages += 1;
                    last_msg_added_epos = nl_pos + 1;
                } else {
                    log::trace!("  determined to be the last line, has new code  {code}");
                    // treat this as a new message
                    // we first push the prev message, if present
                    if message_size > 0 {
                        let message = parse_message(code, buffer, msg_start_pos, message_size)?;
                        log::trace!("  pushing prev to last message {message:?}");
                        unsent_messages.push_back(message);
                        num_messages += 1;
                        // last_msg_added_epos = nl_pos + 1; // not needed as we do this at the end anyway
                    }
                    // now we process the new message
                    code = new_code;
                    msg_start_pos = pos;
                    let message = parse_message(code, buffer, msg_start_pos, message_size)?;
                    log::trace!("  pushing new message {message:?}");
                    if let Message::Ok = message {
                        ok_added = true;
                    }
                    unsent_messages.push_back(message);
                    num_messages += 1;
                    last_msg_added_epos = nl_pos + 1;
                }
                if !ok_added {
                    unsent_messages.push_back(Message::Ok);
                }
                break;
            } else {
                // if this is not the last line
                // if this line is a continuation of the previous one
                if new_code == code {
                    log::trace!("  not the last line, continuing from prev line");
                    // we just mark this line as extension of previous one
                    message_size += nl_pos - pos + 1;
                } else {
                    log::trace!("  not the last line, but new code");
                    // treat this as a new message
                    // we first push the prev message, if present
                    if message_size > 0 {
                        let message = parse_message(code, buffer, msg_start_pos, message_size)?;
                        log::trace!("  pushing new message {message:?}");
                        unsent_messages.push_back(message);
                        num_messages += 1;
                        last_msg_added_epos = line_start_pos;
                    }
                    // now we process the new message
                    log::trace!("  resetting markers for a new message with code {new_code}");
                    code = new_code;
                    message_size = nl_pos - pos;
                    msg_start_pos = pos;
                }
            }
        }
        pos = next_line_pos; // move to the next line
    }

    // push all unprocessed bytes to self.unparsed_bytes
    let remaining = buffer.len() - last_msg_added_epos;
    log::trace!("conn: found {remaining} pending bytes");
    if remaining > 0 {
        unparsed_bytes.clear();
        let src = &buffer[(buffer.len() - remaining)..];
        log::trace!("conn: enqueuing pending: {}", &String::from_utf8_lossy(src));
        unparsed_bytes.extend_from_slice(src);
    }

    Ok(num_messages)
}

/// Parse the 4 digit code at the front of a bird response
#[inline]
fn parse_code(buffer: &[u8]) -> Result<u32> {
    Ok(std::str::from_utf8(&buffer[0..4])?.parse()?)
}

/// Parse a [Message] and return it
#[inline]
fn parse_message(code: u32, buffer: &[u8], start_pos: usize, msg_size: usize) -> Result<Message> {
    let mut v: Vec<u8> = Vec::with_capacity(msg_size);
    let mut idx = 0;
    let mut pos = start_pos;
    while pos < buffer.len() {
        if idx > 0 {
            pos += match buffer[pos] {
                b' ' => 1,
                _ => 5,
            };
            v.push(b'\n'); // this is for the newline needed after previous line
        }
        idx += 1;

        if let Some(nl_pos) = buffer[pos..].iter().position(|it| *it == b'\n') {
            let src = &buffer[pos..(pos + nl_pos)];
            v.extend_from_slice(src);
            pos += src.len() + 1;
            if v.len() == msg_size {
                break;
            }
        } else {
            // we don't see a new line, so this must be the last line
            // so we break at the end of this
            let src = &buffer[pos..];
            v.extend_from_slice(src);
            break;
        }
    }
    Ok(Message::from_code(code, std::str::from_utf8(&v)?))
}

/// Reads are done in sizes of this
const READ_FRAME_SIZE: usize = 2048;

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    /// Handy fn for removing the indents from a multi-line string
    fn heredoc(s: &str) -> String {
        let indent = if let Some(line2) = s.split('\n').nth(2) {
            line2.find(char::is_alphanumeric).unwrap_or(0)
        } else {
            0
        };
        s.lines()
            .map(|x| (if x.starts_with(' ') { &x[indent..] } else { x }).into())
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// The bird response that we test against
    fn get_test_text() -> String {
        let _ = env_logger::try_init();

        heredoc(
            "0001 BIRD 2.0.7 ready.
            show interfaces
            1001-lo up (index=1)
            1004-\tMultiAccess AdminUp LinkUp Loopback Ignored MTU=65536
            1003-\t127.0.0.1/8 (Preferred, scope host)
             \t::1/128 (Preferred, scope host)
            1001-eth0 up (index=2)
            1004-\tMultiAccess Broadcast Multicast AdminUp LinkUp MTU=9000
            1003-\t172.30.0.12/16 (Preferred, scope site)
             \t172.29.1.15/32 (scope univ)
             \t172.29.1.16/32 (scope univ)
             \t172.29.1.17/32 (scope univ)
             \tfe80::4495:80ff:fe71:a791/64 (Preferred, scope link)
             \tfe80::4490::72/64 (scope univ)
            1001-eth1 up (index=3)
            1004-\tMultiAccess Broadcast Multicast AdminUp LinkUp MTU=1500
            1003-\t169.254.199.2/30 (Preferred, opposite 169.254.199.1, scope univ)
             \tfe80::a06f:7ff:fea7:c662/64 (Preferred, scope link)
             \tfe80:169:254:199::2/126 (scope link)
            0000 
            ",
        )
    }

    /// Returns the nth position match as determined by `op`
    fn get_nth_pos<F>(text: &str, n: u32, op: F) -> usize
    where
        F: Fn(&str) -> Option<usize>,
    {
        let mut pos: usize = 0;
        let mut num_match: u32 = 0;
        for line in text.lines() {
            if let Some(x) = op(line) {
                num_match += 1;
                if num_match == n {
                    pos += x;
                    break;
                }
            }
            pos += line.len() + 1;
        }
        pos
    }

    /// Tests parsing of a single line response
    #[test]
    fn test_single_line_parsing() {
        let text = get_test_text();
        let needle = "lo up (index=1)";
        let buffer = text.as_bytes();
        let start_pos = text.find(needle).unwrap();
        let message = parse_message(1001, buffer, start_pos, needle.len())
            .expect("should not have failed parsing");
        if let Message::InterfaceList(s) = message {
            assert_eq!(s, needle);
        } else {
            panic!("incorrect message type {message:?}");
        }
    }

    /// Tests parsing of a multi-line response
    #[test]
    fn test_multi_line_parsing() {
        let text = get_test_text();

        let start_pos = get_nth_pos(&text, 1, |x| {
            if x.ends_with("MTU=9000") {
                Some(x.len())
            } else {
                None
            }
        }) + 6;
        let end_pos = get_nth_pos(&text, 3, |x| {
            if x.starts_with("1001-") {
                Some(0)
            } else {
                None
            }
        }) - 1;
        let buffer = text.as_bytes();
        let msg_size = end_pos
            - start_pos
            - unsafe {
                std::str::from_utf8_unchecked(&buffer[start_pos..end_pos])
                    .matches('\n')
                    .count()
            };
        let message = parse_message(1003, buffer, start_pos, msg_size)
            .expect("should not have failed parsing");
        if let Message::InterfaceAddress(s) = message {
            assert!(s.starts_with("\t172.30.0.12"));
            assert!(s.contains("\n\t172.29.1.15/32 (scope univ)\n"));
            assert!(s.contains("\n\t172.29.1.16/32 (scope univ)\n"));
            assert!(s.contains("\n\t172.29.1.17/32 (scope univ)\n"));
            assert!(s.ends_with("fe80::4490::72/64 (scope univ)"));
            assert!(!s.ends_with('\n'));
        } else {
            panic!("incorrect message type {message:?}");
        }
    }

    /// Tests parsing of a multi-line response that's at the very end
    #[test]
    fn test_multi_line_parsing_at_end() {
        let text = get_test_text().replace("\n0000 \n", "");
        let start_pos = get_nth_pos(&text, 3, |x| {
            if x.starts_with("1003-") {
                Some(0)
            } else {
                None
            }
        }) + 5;
        let end_pos = text.len();
        let buffer = text.as_bytes();
        let msg_size = end_pos
            - start_pos
            - unsafe {
                std::str::from_utf8_unchecked(&buffer[start_pos..end_pos])
                    .matches('\n')
                    .count()
            };
        let message = parse_message(1003, buffer, start_pos, msg_size)
            .expect("should not have failed parsing");
        if let Message::InterfaceAddress(s) = message {
            assert!(s.starts_with("\t169.254.199.2"));
            assert!(s.contains("\n\tfe80::a06f:7ff:fea7:c662/64 (Preferred, scope link)\n"));
            assert!(s.contains("\n\tfe80:169:254:199::2/126 (scope link)"));
            assert!(!s.ends_with('\n'));
        } else {
            panic!("incorrect message type {message:?}");
        }
    }
}
