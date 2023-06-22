/**
 * @author: David Hammer
 * @desc: Simple DNS server following `https://implement-dns.wizardzines.com`
 */
import dgram from 'node:dgram';
import {Buffer} from 'node:buffer';

const Constant = {
    TYPE_A: 1,
    CLASS_IN: 1,
    RECURSION_DESIRED: 1 << 8,
    MAX_UINT16: 65535,
}

class DNSHeader {
    id;
    flags;
    num_questions;
    num_answers;
    num_authorities;
    num_additionals;
    
    field_count = 6;

    constructor(id,
            flags,
            num_questions = 0,
            num_answers = 0,
            num_authorities = 0,
            num_additionals = 0) {
        this.id = id;
        this.flags = flags;
        this.num_questions = num_questions;
        this.num_answers = num_answers;
        this.num_authorities = num_authorities;
        this.num_additionals = num_additionals;
    }

    toBytes() {
        const buf = Buffer.alloc(this.field_count * 2);
        buf.writeUInt16BE(this.id, 0);
        buf.writeUInt16BE(this.flags, 2);
        buf.writeUInt16BE(this.num_questions, 4);
        buf.writeUInt16BE(this.num_answers, 6);
        buf.writeUInt16BE(this.num_authorities, 8);
        buf.writeUInt16BE(this.num_additionals, 10);
        return buf;
    }
}

class DNSQuestion {
    name;
    type;
    class_;
    constructor(name, type, class_) {
        this.name = name;
        this.type = type;
        this.class_ = class_;
    }

    toBytes() {
        const buf = Buffer.alloc(4);
        buf.writeUInt16BE(this.type, 0);
        buf.writeUInt16BE(this.class_, 2);
        return Buffer.concat([encodeDNSName(this.name), buf]);
    } 
}

class DNSRecord {
    name;
    type;
    class_;
    ttl;
    data;
    constructor(name, type, class_, ttl, data) {
        this.name = name;
        this.type = type;
        this.class_ = class_;
        this.ttl = ttl;
        this.data = this.ipToString(data);
    }

    ipToString(ipBuf) {
        const arr = [];
        for (const val of ipBuf.values()) {
            arr.push(val.toString());
        }
        return arr.join('.');
    }
}

class DNSPacket {
    header;
    questions = [];
    answers = [];
    authorities = [];
    additionals = [];

    constructor(header, questions, answers, authorities, additionals) {
        this.header = header;
        this.questions = questions;
        this.answers = answers;
        this.authorities = authorities;
        this.addtionals = additionals;
    }
}

function encodeDNSName(domainName) {
    const bufs = domainName.split('.')
        .map(part => {
            const partLength = Buffer.alloc(1);
            partLength.writeUInt8(part.length, 0)
            return Buffer.concat([
                partLength,                   
                Buffer.from(part, 'ascii')
            ]);  
        });
    return Buffer.concat([...bufs, Buffer.alloc(1)]);
}

function decodeName(buf, i) {
    let len;
    const parts = [];
    while ((len = buf.readUInt8(i++)) !== 0) {
        if (len & 0b11000000) { // found compressed name.
            const pointerBuf = Buffer.alloc(2);
            pointerBuf.writeUInt8(len & 0b00111111, 0);
            pointerBuf.writeUInt8(buf.readUInt8(i++), 1);
            const nameLoc = pointerBuf.readUInt16BE();
            const result = decodeName(buf, nameLoc);
            result.i = i;
            return result;
        }
        parts.push(buf.subarray(i, i + len));
        parts.push(Buffer.alloc(1, '.'));
        i += len;
    } 
    parts.pop(); // trailing '.'
    const nameBuf = Buffer.concat(parts);
    return {nameBuf, i};
}

function buildQuery(domainName, recordType) {
    const id = getRandomInt(Constant.MAX_UINT16);
    const header = new DNSHeader(id, Constant.RECURSION_DESIRED, 1 /* num_questions */);
    const question = new DNSQuestion(domainName, recordType, Constant.CLASS_IN);
    return Buffer.concat([header.toBytes(), question.toBytes()]);
}

function parseHeader(buf, start) {
    const id = buf.readUInt16BE(start);
    const flags = buf.readUInt16BE(start+2);
    const num_questions = buf.readUInt16BE(start+4);
    const num_answers = buf.readUInt16BE(start+6);
    const num_authorities = buf.readUInt16BE(start+8);
    const num_additionals = buf.readUInt16BE(start+10);
    const i = start + 12;
    const header = new DNSHeader(id, flags, num_questions, num_answers, num_authorities, num_additionals);
    return {i, header};
}

function parseQuestion(buf, start) {
    let {nameBuf, i} = decodeName(buf, start);
    const type = buf.readUInt16BE(i);
    const class_ = buf.readUInt16BE(i+2);
    i += 4;
    const question = new DNSQuestion(nameBuf.toString(), type, class_);
    return {i, question}; 
}

function parseRecord(buf, start) {
    let {nameBuf, i} = decodeName(buf, start);
    const type = buf.readUInt16BE(i);
    const class_ = buf.readUInt16BE(i+2);
    const ttl = buf.readUInt32BE(i+4);
    const data_len = buf.readUInt16BE(i+8);
    const data = buf.subarray(i+10, i+10+data_len);
    i += 10 + data_len;
    const record = new DNSRecord(nameBuf.toString(), type, class_, ttl, data);
    return {i, record};
}

function parsePacket(buf) {
    const questions = [];
    const answers = [];
    const authorities = [];
    const additionals = [];

    let i = 0;
    const headerResp = parseHeader(buf, i)
    i = headerResp.i;
    const header = headerResp.header;
    for (let j = 0; j < header.num_questions; j++) {
        const questionResp = parseQuestion(buf, i);
        questions.push(questionResp.question);
        i = questionResp.i;
    }
    for (let j = 0; j < header.num_answers; j++) {
        const recordResp = parseRecord(buf, i);
        answers.push(recordResp.record);
        i = recordResp.i;
    }
    for (let j = 0; j < header.num_authorities; j++) {
        const recordResp = parseRecord(buf, i);
        authorities.push(recordResp.record);
        i = recordResp.i;
    }
    for (let j = 0; j < header.num_additionals; j++) {
        const recordResp = parseRecord(buf, i);
        additionals.push(recordResp.record);
        i = recordResp.i;
    }
    return new DNSPacket(header, questions, answers, authorities, additionals);
}

function getRandomInt(max) {
    return Math.floor(Math.random() * max);
  }

function findIPAddress(name) {
    const client = dgram.createSocket('udp4');
    const message = buildQuery(name, Constant.TYPE_A);
    const host = '8.8.8.8';
    const port = 53;

    client.send(message, 0, message.length, port, host, function(err, bytes) {
        if (err) throw err;
        // console.log('UDP message sent to ' + host + ':' + port);
    });

    client.on('message', function (message, remote) {
        // console.log(remote.address + ':' + remote.port + ' - response received');
        const packet = parsePacket(message);
        console.log(`${name}: ${packet.answers[0].data}`);
        client.close();
    });
}

findIPAddress("www.example.com");
findIPAddress("www.google.com");
findIPAddress("maps.google.com");

