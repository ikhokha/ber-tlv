import { ITlv, TlvType } from './Tlv';

import { OctetBuffer } from '@ikhokha/octet-buffer';

class TlvSerializerSerializeError implements Error {
    constructor(public name: string, public message: string) {}

    static errorPayloadToBig(tag: string, requested: number, maximum: number): TlvSerializerSerializeError {
      return new TlvSerializerSerializeError('Error while serializing item ' + tag + '"', 'Provided length is ' + requested + ', maximum supported ' + maximum);
    }
}

const TLV_SERIALIZE_MULTIBYTE_FLAG = 0x80;
const SERIALIZE_UINT8_MAX: number = 0xFF;
const SERIALIZE_UINT16_MAX: number = 0xFFFF;
const SERIALIZE_UINT24_MAX: number = 0xFFFFFF;
const SERIALIZE_UINT32_MAX: number = 0xFFFFFFFF;

export class TlvSerializer {

    static serializeItems(items: ITlv[]): Buffer {
        const serializedItems: Buffer[] = [];
        for (const item of items){
            const itemBuffer: Buffer = TlvSerializer.serializeItem(item);
            serializedItems.push(itemBuffer);
        }

        const serializedBuffer = Buffer.concat(serializedItems);
        return serializedBuffer;
    }

    static serializeItem(item: ITlv): Buffer {
        let serializedItem: Buffer;
        if (item.type === TlvType.CONSTRUCTED){
            serializedItem = TlvSerializer.serializeConstrucedItem(item);
        } else {
            serializedItem = TlvSerializer.serializePrimitiveItem(item);
        }

        return serializedItem;
    }

    static serializeConstrucedItem(item: ITlv): Buffer {
        let serializedItems: Buffer[] = [];
        for (const subitem of item.items ?? []){
            const itemBuffer: Buffer = TlvSerializer.serializeItem(subitem);
            serializedItems.push(itemBuffer);
        }
        const serializedItemsBuffer = Buffer.concat(serializedItems);

        const tagBuffer: Buffer = Buffer.from(item.tag, 'hex');
        const lengthBuffer: Buffer = this.lengthBufferForLengt(item.tag, serializedItemsBuffer.length);

        const serializedItem: Buffer = Buffer.concat([tagBuffer, lengthBuffer, serializedItemsBuffer]);
        return serializedItem;
    }

    static serializePrimitiveItem(item: ITlv): Buffer {
        const tagBuffer: Buffer = Buffer.from(item.tag, 'hex');
        const lengthBuffer: Buffer = this.lengthBufferForLengt(item.tag, item.value?.length ?? 0);

        const serializedItem: Buffer = Buffer.concat([tagBuffer, lengthBuffer, item.value ?? Buffer.alloc(0)]);
        return serializedItem;
    }

    static lengthBufferForLengt(tag: string, length: number): Buffer{
        const octetBuffer: OctetBuffer = new OctetBuffer(Buffer.alloc(1));

        if (length < TLV_SERIALIZE_MULTIBYTE_FLAG){
            octetBuffer.writeUInt8(length);
        }
        else if (length <= SERIALIZE_UINT8_MAX){
            octetBuffer.writeUInt8(TLV_SERIALIZE_MULTIBYTE_FLAG | 0x01);
            octetBuffer.writeUInt8(length);
        }
        else if (length <= SERIALIZE_UINT16_MAX){
          octetBuffer.writeUInt8(TLV_SERIALIZE_MULTIBYTE_FLAG | 0x02);
          octetBuffer.writeUInt16(length);
        }
        else if (length <= SERIALIZE_UINT24_MAX){
          octetBuffer.writeUInt8(TLV_SERIALIZE_MULTIBYTE_FLAG | 0x03);
          octetBuffer.writeUInt24(length);
        }
        else if (length <= SERIALIZE_UINT32_MAX){
          octetBuffer.writeUInt8(TLV_SERIALIZE_MULTIBYTE_FLAG | 0x04);
          octetBuffer.writeUInt32(length);
        }
        else {
            throw TlvSerializerSerializeError.errorPayloadToBig(tag, length, SERIALIZE_UINT32_MAX);
        }

        return octetBuffer.backingBuffer;
    }

}
