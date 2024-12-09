import net from "net";
import { EventEmitter } from "events";
import mysql from "mysql2";
import "dotenv/config";
import fs from "fs";
import cron from "node-cron";

const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const log = (...args: any[]) => {
  console.log(...args);
  // fs.appendFileSync("./.log", `${JSON.stringify(args)}\n`);
};

interface ReturnedData {
  data: Buffer;
  finished: boolean;
}

interface Packet {
  tag: Buffer;
  size: number;
  reply_code: number;
  checksum: number;
  session_code: number;
  reply_counter: number;
  data: Buffer;
}

class ZKTeco extends EventEmitter {
  public isConnected = false;
  private wasConnected = false;
  private clientSocket: net.Socket;
  private session_id: number = 0;
  private reply_number: number = 0;
  private packetList = {};
  private internalBuffer: Buffer = Buffer.alloc(0);

  private USHORT_SIZE = 0xffff;
  private EMPTY_BUFFER = Buffer.from([]);

  private START_TAG = Buffer.from([0x50, 0x50, 0x82, 0x7d]);
  private CMD_CONNECT = 0x03e8;
  private CMD_DISCONNECT = 0x03e9;
  private CMD_ACK_OK = 0x07d0;
  private CMD_ACK_UNAUTH = 0x07d5;
  private CMD_OPTIONS_WRQ = 0x000c;
  private CMD_OPTIONS_RRQ = 0x000b;
  private CMD_REFRESHOPTION = 0x03f6; // does not work
  private CMD_REG_EVENT = 0x01f4;
  private CMD_DATA_WRRQ = 0x05df;
  private CMD_DATA_RDY = 0x05e0;
  private CMD_PREPARE_DATA = 0x05dc;
  private CMD_DATA = 0x05dd;
  private CMD_FREE_DATA = 0x05de;
  private CMD_ENABLEDEVICE = 0x03ea;
  private CMD_DISABLEDEVICE = 0x03eb;
  private CMD_ATTLOG_RRQ = 0x000d;
  private CMD_GET_FREE_SIZES = 0x0032;
  private CMD_GET_TIME = 0x00c9;
  private CMD_SET_TIME = 0x00ca;
  private CMD_RESTART = 0x03ec;

  private EF_ATTLOG = 1;

  private debugPacket(packet: Buffer, direction: "SEND" | "RECV") {
    const reply_code = packet.readUInt16LE(8);
    const checksum = packet.readUInt16LE(10);
    const session_code = packet.readUInt16LE(12);
    const reply_counter = packet.readUInt16LE(14);
    const data = packet.slice(16);
    let reply_code_str = "";

    switch (reply_code) {
      case this.CMD_CONNECT:
        reply_code_str = "CMD_CONNECT";
        break;
      case this.CMD_DISCONNECT:
        reply_code_str = "CMD_DISCONNECT";
        break;
      case this.CMD_ACK_OK:
        reply_code_str = "CMD_ACK_OK";
        break;
      case this.CMD_ACK_UNAUTH:
        reply_code_str = "CMD_ACK_UNAUTH";
        break;
      case this.CMD_OPTIONS_WRQ:
        reply_code_str = "CMD_OPTIONS_WRQ";
        break;
      case this.CMD_OPTIONS_RRQ:
        reply_code_str = "CMD_OPTIONS_RRQ";
        break;
      case this.CMD_REFRESHOPTION:
        reply_code_str = "CMD_REFRESHOPTION";
        break;
      case this.CMD_REG_EVENT:
        reply_code_str = "CMD_REG_EVENT";
        break;
      case this.CMD_DATA_WRRQ:
        reply_code_str = "CMD_DATA_WRRQ";
        break;
      case this.CMD_DATA_RDY:
        reply_code_str = "CMD_DATA_RDY";
        break;
      case this.CMD_PREPARE_DATA:
        reply_code_str = "CMD_PREPARE_DATA";
        break;
      case this.CMD_DATA:
        reply_code_str = "CMD_DATA";
        break;
      case this.CMD_FREE_DATA:
        reply_code_str = "CMD_FREE_DATA";
        break;
      case this.CMD_ENABLEDEVICE:
        reply_code_str = "CMD_ENABLEDEVICE";
        break;
      case this.CMD_DISABLEDEVICE:
        reply_code_str = "CMD_DISABLEDEVICE";
        break;
      case this.CMD_ATTLOG_RRQ:
        reply_code_str = "CMD_ATTLOG_RRQ";
        break;
      case this.CMD_GET_FREE_SIZES:
        reply_code_str = "CMD_GET_FREE_SIZES";
        break;
      case this.CMD_GET_TIME:
        reply_code_str = "CMD_GET_TIME";
        break;
      case this.CMD_SET_TIME:
        reply_code_str = "CMD_SET_TIME";
        break;
      case this.CMD_RESTART:
        reply_code_str = "CMD_RESTART";
        break;

      default:
        reply_code_str = `UNKNOWN (0x${reply_code.toString(16)})`;
        break;
    }

    log(
      direction === "SEND" ? "SEND" : "RECV",
      `${direction === "SEND" ? "command" : "reply"}: ${reply_code_str}`,
      `checksum: ${checksum}`,
      `session_code: ${session_code}`,
      `reply_id: ${reply_counter}`,
      `data: ${data.slice(0, 32).toString("hex")} ...`,
    );
  }

  private checksum16(payload: Buffer): number {
    let chk_32b = 0;
    let j = 1;

    if (payload.length % 2 === 1)
      payload = Buffer.concat([payload, Buffer.from([0x00])]);

    // exclude checksum field
    payload.writeUInt16LE(0x00, 2);

    while (j < payload.length) {
      // extract short integer, in little endian, from payload
      let num_16b = payload[j - 1] + (payload[j] << 8);
      // add to 32-bit checksum
      chk_32b += num_16b;
      j += 2;
    }

    chk_32b = (chk_32b & 0xffff) + ((chk_32b & 0xffff0000) >> 16);

    let chk_16b = chk_32b ^ 0xffff;

    return chk_16b;
  }

  private create_packet(command: number, data: Buffer) {
    const chunks = [];
    let temp;

    chunks.push(this.START_TAG); //fixed tag
    chunks.push(Buffer.from([0x00, 0x00])); // size of payload
    chunks.push(Buffer.from([0x00, 0x00])); // fixed zeros

    // cmd code / reply id
    temp = Buffer.from([0x00, 0x00]);
    temp.writeUInt16LE(command, 0);
    chunks.push(temp);

    chunks.push(Buffer.from([0x00, 0x00])); // checksum field

    temp = Buffer.from([0x00, 0x00]);
    temp.writeUint16LE(this.session_id);
    chunks.push(temp); // session id

    temp = Buffer.from([0x00, 0x00]);
    temp.writeUint16LE(this.reply_number);
    chunks.push(temp); // reply id

    // additional data
    if (data) chunks.push(data);

    const packet = Buffer.concat(chunks);

    // write size field
    packet.writeUInt16LE(packet.length - 8, 4);

    // write checksum
    packet.writeUInt16LE(this.checksum16(packet.slice(8)), 10);

    return packet;
  }

  private send_command(command: number, data: Buffer, callback) {
    this.reply_number =
      command === this.CMD_CONNECT ||
      command === this.CMD_ACK_OK ||
      command === this.CMD_ACK_UNAUTH
        ? 0
        : (this.reply_number + 1) % this.USHORT_SIZE;
    const packet = this.create_packet(command, data);
    this.debugPacket(packet, "SEND");

    this.clientSocket.write(packet);
    this.packetList[this.reply_number] = { packet, callback };
  }

  private bufferFromString(data: string): Buffer {
    const result = [];
    for (let i = 0; i < data.length; i++) {
      result.push(data.charCodeAt(i));
    }
    return Buffer.from(result);
  }

  private read(buffer: Buffer) {
    // log2(buffer.toString("hex"));

    this.internalBuffer = Buffer.concat([this.internalBuffer, buffer]);

    while (this.internalBuffer.length >= 8) {
      const packet_size = 8 + this.internalBuffer.readInt32LE(4);
      if (packet_size > this.internalBuffer.length) break;
      const packet = this.internalBuffer.slice(0, packet_size);
      this.internalBuffer = this.internalBuffer.slice(packet_size);
      this.debugPacket(packet, "RECV");
      this.handle_packet(packet);
    }
  }

  private handle_packet(buffer: Buffer) {
    const packet: Packet = {
      tag: buffer.slice(0, 4),
      size: buffer.readUInt32LE(4),
      reply_code: buffer.readUInt16LE(8),
      checksum: buffer.readUInt16LE(10),
      session_code: buffer.readUInt16LE(12),
      reply_counter: buffer.readUInt16LE(14),
      data: buffer.slice(16),
    };

    // check checksum
    const chk = this.checksum16(buffer.slice(8));
    if (chk !== packet.checksum) {
      log(
        `Invalid checksum: ${chk.toString(16)} != ${packet.checksum.toString(
          16,
        )}`,
      );
      // return;
    }

    switch (packet.reply_code) {
      case this.CMD_ACK_OK:
      case this.CMD_ACK_UNAUTH:
      case this.CMD_PREPARE_DATA:
      case this.CMD_DATA:
      case this.CMD_FREE_DATA:
        if (
          typeof this.packetList[packet.reply_counter].callback === "function"
        )
          this.packetList[packet.reply_counter].callback(packet);
        break;
      case this.CMD_REG_EVENT:
        this.parseEvent(packet);
        break;

      default:
        const error = {
          code: "UNKNOWN_COMMAND",
          message: "Unknown command",
          packet,
        };
        this.packetList[packet.reply_counter].callback(packet, error);
        log("Unknown command: " + packet.reply_code.toString(16));
        break;
    }
  }

  public async connect(address: string, port: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.session_id = 0;
      this.reply_number = 0;
      this.clientSocket = new net.Socket();
      this.clientSocket.setTimeout(3000);
      this.clientSocket.setKeepAlive(true);
      this.clientSocket.connect(port, address, () => {
        if (this.session_id !== 0) {
          this.disconnect();
        }

        this.send_command(this.CMD_CONNECT, this.EMPTY_BUFFER, (res, err) => {
          this.session_id = res.session_code;

          if (err) return reject(err);

          this.send_command(
            this.CMD_OPTIONS_WRQ,
            this.bufferFromString("SDKBuild=1\0"),
            (res, err) => {
              if (err) return reject(err);
              this.isConnected = true;
              return resolve();
            },
          );
        });
      });

      this.clientSocket.on("data", (data) => {
        this.read(data);
      });

      this.clientSocket.on("error", (error) => {
        this.clientSocket.destroy();
        this.isConnected = false;
        this.emit("error", error);
        log("Error: " + error);
      });

      this.clientSocket.on("connect", () => {
        this.wasConnected = true;
        this.isConnected = true;
      });

      this.clientSocket.on("close", () => {
        if (this.wasConnected) {
          this.wasConnected = false;
          this.isConnected = false;
          this.emit("close");
        }
      });
    });
  }

  public async disconnect(): Promise<void> {
    return new Promise(async (resolve, reject) => {
      if (this.isConnected)
        this.send_command(this.CMD_DISCONNECT, Buffer.from([]), () => {});
      // wait 10 seconds for disconnect
      await new Promise((resolve) => setTimeout(resolve, 10000));
      this.clientSocket.end();
      this.packetList = {};
      this.emit("disconnect");
      this.isConnected = false;
      await new Promise((resolve) => setTimeout(resolve, 1000));
      resolve();
    });
  }

  private async getDeviceInfo(param_name: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.send_command(
        this.CMD_OPTIONS_RRQ,
        this.bufferFromString(param_name + "\0"),
        (res) => {
          const data: Buffer = res.data;
          resolve(
            data
              .toString("ascii")
              .split("=")[1]
              .replace(/\u0000/g, ""),
          );
        },
      );
    });
  }

  public async getSerialNumber(): Promise<string> {
    return this.getDeviceInfo("~SerialNumber");
  }

  public async enableRealTime(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.send_command(
        this.CMD_REG_EVENT,
        Buffer.from([0xff, 0xff, 0x00, 0x00]),
        (res, err) => {
          if (err) return reject(err);
          return resolve();
        },
      );
    });
  }

  private parseEvent(packet) {
    switch (packet.session_code) {
      case this.EF_ATTLOG:
        const data: Buffer = packet.data;

        const user_id = data.toString("ascii", 0, 9).replace(/\u0000/g, "");

        const att_state = data.readUInt8(24);
        const verify_type = data.readUInt8(25);
        const year = data.readUInt8(26) + 2000;
        const month = data.readUInt8(27);
        const day = data.readUInt8(28);
        const hour = data.readUInt8(29);
        const minute = data.readUInt8(30);
        const second = data.readUInt8(31);

        const event = {
          user_id,
          att_state,
          verify_type,
          date: `${year}-${month}-${day} ${hour}:${minute}:${second}`,
        };

        this.emit("attendance", event);
        break;
    }
  }

  public async readAllUserIds(): Promise<any> {
    let buffer = await this.readLargeData(
      Buffer.from("0109000500000000000000", "hex"),
    );
    return this.parseUsers(buffer);
  }

  private parseUsers(data: Buffer): any {
    const dataLen = data.length;

    const users = {};

    // skip first 4 bytes (size + zeros)
    let i = 4;
    while (i < dataLen) {
      // extract serial number
      const userSN = data.readUInt16LE(i);

      // extract permission token
      const permToken = data[i + 2];

      // extract user password, if it is invalid, stores ''
      let password = "";
      if (data[i + 3] !== 0x00) {
        password = data.toString("ascii", i + 3, i + 11).replace(/\0/g, "");
      }

      // extract user name
      const userName = data
        .toString("utf-8", i + 11, i + 35)
        .replace(/\0/g, "");

      // extract card number
      const cardNumber = data.readUInt32LE(i + 35);

      // extract group number
      const groupNumber = data[i + 39];

      // extract user timezones if they exists
      let userTimezones = [];
      if (data.readUint16LE(i + 40) === 1) {
        userTimezones = [0, 0, 0];
        userTimezones[0] = data.readUInt16LE(i + 42);
        userTimezones[1] = data.readUInt16LE(i + 44);
        userTimezones[2] = data.readUInt16LE(i + 46);
      }

      // extract the user id
      const userId = data.toString("ascii", i + 48, i + 56).replace(/\0/g, "");

      users[userSN] = {
        userId,
        userSN,
        userName,
        password,
        cardNumber,
        admin_lv: permToken >> 1,
        neg_enabled: permToken & 0x01,
        groupNumber,
        userTimezones,
      };

      i += 72;
    }

    return users;
  }

  public async disableDevice(timer?: number): Promise<void> {
    return new Promise((resolve, reject) => {
      let data = Buffer.alloc(0);
      if (timer) {
        const data = Buffer.alloc(4);
        data.writeUInt32LE(timer, 0);
      }
      this.send_command(this.CMD_DISABLEDEVICE, data, (res, err) => {
        if (err) return reject(err);
        return resolve();
      });
    });
  }

  public async enableDevice(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.send_command(
        this.CMD_ENABLEDEVICE,
        this.EMPTY_BUFFER,
        (res, err) => {
          if (err) return reject(err);
          return resolve();
        },
      );
    });
  }

  private async readLargeData(command_payload: Buffer): Promise<Buffer> {
    let first = true;
    let buffer = Buffer.alloc(0);
    return new Promise((resolve, reject) => {
      this.send_command(this.CMD_DATA_WRRQ, command_payload, (res, err) => {
        if (err) return reject(err);

        if (res.reply_code === this.CMD_DATA && first) {
          // Small dataset in one packet
          return resolve(res.data);
        } else {
          // Large dataset
          if (first && res.reply_code !== this.CMD_ACK_OK) {
            return reject("Invalid data");
          }

          const size_dataset1 = res.data.readUInt32LE(1);
          const size_dataset2 = res.data.readUInt32LE(5);
          if (size_dataset1 !== size_dataset2) {
            return reject("Size not matching");
          }

          const rdy = Buffer.alloc(8);
          rdy.writeUInt32LE(size_dataset1, 4);

          this.send_command(this.CMD_DATA_RDY, rdy, (res, err) => {
            if (err) return reject(err);

            if (res.reply_code === this.CMD_PREPARE_DATA) {
              // Do nothing, it just returns data size
            }

            if (res.reply_code === this.CMD_DATA) {
              buffer = Buffer.concat([buffer, res.data]);
            }

            if (res.reply_code === this.CMD_ACK_OK) {
              log("Data received. Size: " + buffer.length);

              this.send_command(
                this.CMD_FREE_DATA,
                this.EMPTY_BUFFER,
                (res, err) => {
                  return resolve(buffer);
                },
              );
            }
          });
        }

        first = false;
      });
    });
  }

  public async readAttendance(): Promise<any> {
    let buffer = await this.readLargeData(
      Buffer.from("010d000000000000000000", "hex"),
    );
    return this.parseAttLog(buffer);
  }

  public async readRecords(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.send_command(
        this.CMD_GET_FREE_SIZES,
        this.EMPTY_BUFFER,
        (res, err) => {
          if (err) return reject(err);

          const records = res.data.readUInt32LE(64);
          log("records", records);

          return resolve(records);
        },
      );
    });
  }

  public async getDeviceDataSizes(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.send_command(
        this.CMD_GET_FREE_SIZES,
        this.EMPTY_BUFFER,
        (res, err) => {
          if (err) return reject(err);

          const sizes = {
            admin_count: res.data.readUInt32LE(48),
            user_count: res.data.readUInt32LE(16),
            user_capacity: res.data.readUInt32LE(60),
            user_remaining: res.data.readUInt32LE(72),
            fingerprint_count: res.data.readUInt32LE(24),
            fingerprint_capacity: res.data.readUInt32LE(56),
            fingerprint_remaining: res.data.readUInt32LE(68),
            password_count: res.data.readUInt32LE(52),
            operation_count: res.data.readUInt32LE(40),
            attendance_count: res.data.readUInt32LE(32),
            attendance_capacity: res.data.readUInt32LE(64),
            attendance_remaining: res.data.readUInt32LE(76),
            face_count: res.data.readUInt32LE(80),
            face_capacity: res.data.readUInt32LE(88),
          };

          return resolve(sizes);
        },
      );
    });
  }

  public decodeTime(time: number): string {
    let t = time;
    let s = t % 60;
    t = Math.floor(t / 60);
    let m = t % 60;
    t = Math.floor(t / 60);
    let h = t % 24;
    t = Math.floor(t / 24);
    const d = (t % 31) + 1;
    t = Math.floor(t / 31);
    const mth = (t % 12) + 1;
    t = Math.floor(t / 12);
    const y = t + 2000;
    const timestamp = `${y}-${mth}-${d} ${h}:${m}:${s}`;
    return timestamp;
  }

  public encodeTime(time: Date): number {
    const d =
      ((time.getFullYear() % 100) * 12 * 31 +
        time.getMonth() * 31 +
        time.getDate() -
        1) *
        (24 * 60 * 60) +
      (time.getHours() * 60 + time.getMinutes()) * 60 +
      time.getSeconds();
    return d;
  }

  private parseAttLog(data: Buffer): any {
    // log("parseAttLog", data.toString("hex"));
    const attLog = [];
    log("Parsing records");

    data = data.slice(4);

    while (data.length >= 40) {
      const uid = data.readUInt16LE(0);

      let user_id = data.toString("ascii", 2, 26).replace(/\0/g, "");
      // user_id = (user_id.split(b'\x00')[0]).decode(errors='ignore')
      const status = data.readUInt8(26);
      let t = data.readUint32LE(27);
      let s = t % 60;
      t = Math.floor(t / 60);
      let m = t % 60;
      t = Math.floor(t / 60);
      let h = t % 24;
      t = Math.floor(t / 24);
      const d = (t % 31) + 1;
      t = Math.floor(t / 31);
      const mth = (t % 12) + 1;
      t = Math.floor(t / 12);
      const y = t + 2000;
      const timestamp = `${y}-${mth}-${d} ${h}:${m}:${s}`;

      const punch = data.readUInt8(31);
      const space = data.toString("ascii", 32, 40).replace(/\0/g, "");

      data = data.slice(40);
      const record = { uid, user_id, status, timestamp, punch, space };
      attLog.push(record);
    }

    return attLog;
  }

  public async checkConnection(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      let timeout = setTimeout(() => {
        return resolve(false);
      }, 10000);

      this.send_command(
        this.CMD_OPTIONS_RRQ,
        this.bufferFromString("~SerialNumber\0"),
        (res) => {
          clearTimeout(timeout);
          return resolve(true);
        },
      );
    });
  }

  public async getDeviceTime(): Promise<string> {
    return new Promise((resolve, reject) => {
      this.send_command(this.CMD_GET_TIME, this.EMPTY_BUFFER, (res, err) => {
        if (err) return reject(err);
        const timestamp = this.decodeTime(res.data.readUInt32LE(0));
        return resolve(timestamp);
      });
    });
  }

  public async setDeviceTime(timestamp: Date): Promise<any> {
    return new Promise((resolve, reject) => {
      const data = this.encodeTime(timestamp);
      const buffer = Buffer.alloc(4);
      buffer.writeUInt32LE(data, 0);
      this.send_command(this.CMD_SET_TIME, buffer, (res, err) => {
        if (err) return reject(err);
        return resolve(res);
      });
    });
  }

  public async restartDevice(): Promise<void> {
    // The device will not acknowledge the restart command, so we just send it and wait for a few seconds
    this.send_command(this.CMD_RESTART, this.EMPTY_BUFFER, () => {});
    await new Promise((resolve) => setTimeout(resolve, 20000));
  }
}

async function main() {
  let _mysqlConnection: mysql.Connection;

  const getMysqlConnection = async () => {
    const disconnected = async () => {
      return new Promise((resolve) => {
        _mysqlConnection.ping((err) => {
          resolve(err ? true : false);
        });
      });
    };

    if (!_mysqlConnection || (await disconnected())) {
      _mysqlConnection = mysql.createConnection({
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT),
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
      });
    }

    return _mysqlConnection;
  };

  const z = new ZKTeco();

  z.on("close", async () => {
    clearInterval(connectionCheckInterval);
    await z.disconnect();
    connect();
    log("reconnecting...");
  });

  z.on("attendance", async (event) => {
    log({
      rnd: Math.random(),
      event,
    });

    const connection = await getMysqlConnection();
    connection.execute(
      "INSERT IGNORE INTO `attendance` (`date`, `user_id`, `verify_type`) VALUES (?, ?, ?);",
      [event.date, event.user_id, event.att_state],
      function (err, results, fields) {
        if (err) log(err);

        log(results); // results contains rows returned by server
        // If you execute same statement again, it will be picked from a LRU cache
        // which will save query preparation time and give better performance
      },
    );

    const response = await fetch(
      "https://hr.lamah.ly/api/method/hrms.hr.doctype.employee_checkin.employee_checkin.add_log_based_on_employee_field",
      {
        method: "POST",
        body: JSON.stringify({
          employee_field_value: event.user_id,
          timestamp: event.date,
        }),
        headers: {
          "Content-Type": "application/json",
          Authorization: `token ${process.env.API_KEY}:${process.env.API_SECRET}`,
        },
      },
    );
    const data = await response.json();

    log("data: ", data);
  });

  let sync = async () => {
    log("synching attendance log");
    await z.disableDevice();
    let attLog = [];
    try {
      attLog = await z.readAttendance();
    } finally {
      await z.enableDevice();
    }
    for (const att of attLog) {
      const connection = await getMysqlConnection();
      connection.execute(
        "INSERT IGNORE INTO `attendance` (`date`, `user_id`, `verify_type`) VALUES (?, ?, ?);",
        [att.timestamp, att.user_id, att.status],
        function (err, results, fields) {
          if (err) log(err);
          // log(results); // results contains rows returned by server
          // If you execute same statement again, it will be picked from a LRU cache
          // which will save query preparation time and give better performance
        },
      );
    }
    log("finished synching");
  };

  const connect = async () => {
    log("trying to connect...");
    await z.connect(process.env.DEVICE_IP, parseInt(process.env.DEVICE_PORT));
    log("Connected");

    const sizes = await z.getDeviceDataSizes();
    log(sizes);

    await z.disableDevice();
    try {
      const users = await z.readAllUserIds();
      log(`Users Count: ${Object.keys(users).length}`);
    } catch (error) {
      log("Error reading users: ", error);
    } finally {
      await z.enableDevice();
    }
    await z.enableRealTime();

    // start synching
    await sync();

    await z.setDeviceTime(new Date());
  };

  let connectionCheckInterval = setInterval(async () => {
    if (!z.isConnected || !(await z.checkConnection())) {
      if (z.isConnected) {
        await z.disconnect();
      }
      await connect();
    }
  }, 1000 * 60 * 30);

  process.on("uncaughtException", function (err: any) {
    if (err.code === "ETIMEDOUT" && err.address === process.env.DEVICE_IP) {
      log("Connection timed out, reconnecting...");
      // connect();
    }
  });

  process.on("SIGINT", async () => {
    log("Caught interrupt signal");
    clearInterval(connectionCheckInterval);
    if (z && z.isConnected) {
      await z.disconnect();
      // wait promise 1000ms for disconnection
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    process.exit();
  });

  process.on("exit", async () => {
    log("Exiting...");
    clearInterval(connectionCheckInterval);
    if (z && z.isConnected) {
      await z.disconnect();
      // wait promise 1000ms for disconnection
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  });

  await connect();

  // setTimeout(() => {
  //   // restart
  //   z.restartDevice();
  // }, 10000);

  // sync database every day at 01:00 AM
  cron.schedule("0 0 1 * * *", sync);
  // Restart device every day at 06:00 AM
  cron.schedule("0 0 6 * * *", z.restartDevice);
}

main();
