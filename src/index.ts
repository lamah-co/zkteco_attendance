import net from "net";
import { EventEmitter } from "events";
import mysql from "mysql2";
import "dotenv/config";

class ZKTeco extends EventEmitter {
  private wasConnected = false;
  private clientSocket: net.Socket;
  private session_id: number = 0;
  private reply_number: number = 0;
  private packetList = {};
  // private last_reply_code: number = 0;
  // private last_reply_number: number = 0;
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

      default:
        reply_code_str = `UNKNOWN (0x${reply_code.toString(16)})`;
        break;
    }

    console.log(
      direction === "SEND" ? "SEND" : "RECV",
      `${direction === "SEND" ? "command" : "reply"}: ${reply_code_str}`,
      `checksum: ${checksum}`,
      `session_code: ${session_code}`,
      `reply_id: ${reply_counter}`,
      `data: ${data.toString("hex")}`,
    );
  }

  private checksum16(payload: Buffer): number {
    let chk_32b = 0;
    let j = 1;

    if (payload.length % 2 === 1)
      payload = Buffer.concat([payload, Buffer.from([0x00])]);

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
    this.internalBuffer = Buffer.concat([this.internalBuffer, buffer]);

    if (this.internalBuffer.length < 8) return;

    if (!this.internalBuffer.slice(0, 4).equals(this.START_TAG)) {
      this.internalBuffer = Buffer.from([]);
      console.log("Invalid start tag");
      return;
    }

    while (this.internalBuffer.length >= 8) {
      const packetSize = 8 + this.internalBuffer.readUInt16LE(4);
      if (this.internalBuffer.length < packetSize) return;

      const packet = this.internalBuffer.slice(0, packetSize);
      this.internalBuffer = this.internalBuffer.slice(packetSize);

      this.debugPacket(packet, "RECV");
      this.handle_packet(packet);
    }
  }

  private handle_packet(buffer: Buffer) {
    const packet = {
      tag: buffer.slice(0, 4),
      reply_code: buffer.readUInt16LE(8),
      checksum: buffer.readUInt16LE(10),
      session_code: buffer.readUInt16LE(12),
      reply_counter: buffer.readUInt16LE(14),
      data: buffer.slice(16),
    };

    // if (!packet.tag.equals(this.START_TAG)) {
    //   if (
    //     this.last_reply_code === this.CMD_PREPARE_DATA ||
    //     this.last_reply_code === this.CMD_DATA
    //   ) {
    //     if (
    //       typeof this.packetList[this.last_reply_number].callback === "function"
    //     )
    //       this.packetList[this.last_reply_number].callback({
    //         reply_code: 0,
    //         data: buffer,
    //       });
    //     return;
    //   }
    //   console.log("Invalid packet tag");
    // } else {
    //   this.last_reply_code = packet.reply_code;
    //   this.last_reply_number = packet.reply_counter;
    // }

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
        this.emit("info", error);
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
        this.send_command(this.CMD_CONNECT, this.EMPTY_BUFFER, (res, err) => {
          this.session_id = res.session_code;

          if (err) return reject(err);

          this.send_command(
            this.CMD_OPTIONS_WRQ,
            this.bufferFromString("SDKBuild=1\0"),
            (res, err) => {
              if (err) return reject(err);
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
        this.emit("error", error);
        console.log("Error: " + error);
      });

      this.clientSocket.on("connect", () => {
        this.wasConnected = true;
      });

      this.clientSocket.on("close", () => {
        if (this.wasConnected) {
          this.wasConnected = false;
          this.emit("close");
        }
      });
    });
  }

  public async disconnect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.send_command(this.CMD_DISCONNECT, Buffer.from([]), () => {
        this.clientSocket.end();
        this.emit("disconnect");
        resolve();
      });
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

        const user_id = data.toString("ascii", 0, 16).replace(/\u0000/g, "");
        const attState = data.readUInt8(24);
        const verify_type = data.readUInt8(25);
        const year = data.readUInt8(26) + 2000;
        const month = data.readUInt8(27);
        const day = data.readUInt8(28);
        const hour = data.readUInt8(29);
        const minute = data.readUInt8(30);
        const second = data.readUInt8(31);

        const event = {
          user_id,
          attState,
          verify_type,
          date: `${year}-${month}-${day} ${hour}:${minute}:${second}`,
        };

        this.emit("attendance", event);
        break;
    }
  }

  private async readLargeData(res): Promise<Buffer> {
    let preparing = false;
    return new Promise((resolve, reject) => {
      let data: Buffer = Buffer.alloc(0);

      if (res.reply_code === this.CMD_DATA) {
        // device sent the dataset immediately, i.e. short dataset
        data = res.data;
        return resolve(data);
      } else if (res.reply_code === this.CMD_PREPARE_DATA) {
        // seen on fp template download procedure
        // receives packet with long dataset
        preparing = true;
      } else if (res.reply_code === this.CMD_ACK_OK) {
        // device sent the dataset with additional commands, i.e. longer
        // dataset, see ex_data spec
        const sizeInfo = res.data.readUInt32LE(1);

        // creates data for "ready for data" command
        const readyStruct = Buffer.alloc(8);
        readyStruct.writeUInt32LE(sizeInfo, 4);

        let prepareReply = true;
        this.send_command(this.CMD_DATA_RDY, readyStruct, (res, err) => {
          if (err) return reject(err);

          // receives the prepare data reply
          if (prepareReply) {
            prepareReply = false;
          } else {
            // receives packet with long dataset
            if (res.reply_code === this.CMD_DATA) {
              data = Buffer.concat([data, res.data]);
            } else {
              this.send_command(this.CMD_FREE_DATA, this.EMPTY_BUFFER, () => {
                return resolve(data);
              });
            }
          }
        });
      }

      if (preparing) {
        if (res.reply_code !== this.CMD_ACK_OK) {
          // receives packet with long dataset
          data = res.data;
        } else {
          // receives the acknowledge after the dataset packet
          return resolve(data);
        }
      }
    });
  }

  public async readAllUserIds(): Promise<any> {
    let preparing = false;
    return new Promise((resolve, reject) => {
      this.send_command(
        this.CMD_DATA_WRRQ,
        Buffer.from("0109000500000000000000", "hex"),
        (res, err) => {
          if (err) return reject(err);

          this.readLargeData(res).then((data) => {
            return resolve(this.parseUsers(data));
          });
        },
      );
    });
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

  z.on("info", (info) => {
    console.log({ info });
  });

  z.on("close", () => {
    connect();
    console.log("reconnecting...");
  });

  const connect = async () => {
    await z.connect(process.env.DEVICE_IP, parseInt(process.env.DEVICE_PORT));
    console.log("Connected");

    await z.disableDevice();
    const users = await z.readAllUserIds();
    // console.log({ users });
    console.log(`Users Count: ${Object.keys(users).length}`);
    await z.enableDevice();

    await z.enableRealTime();
    z.on("attendance", async (event) => {
      console.log({ event });
      const connection = await getMysqlConnection();
      connection.execute(
        "INSERT INTO `attendance` (`date`, `user_id`, `verify_type`) VALUES (?, ?, ?);",
        [event.date, event.user_id, event.verify_type],
        function (err, results, fields) {
          if (err) console.error(err);

          console.log(results); // results contains rows returned by server
          // If you execute same statement again, it will be picked from a LRU cache
          // which will save query preparation time and give better performance
        },
      );
    });
  };

  process.on("uncaughtException", function (err: any) {
    if (err.code === "ETIMEDOUT" && err.address === process.env.DEVICE_IP) {
      console.log("Connection timed out, reconnecting...");
      connect();
    }
  });

  await connect();
}

main();
