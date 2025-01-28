import { ITlv, TlvType, TlvClass, TlvHelper } from './Tlv';
import { TlvParser, TlvParserResult } from './TlvParser';
import { TlvSerializer } from './TlvSerializer';

export interface IParseError extends Error{
    partialTlv: ITlv[];
}

class TlvFactoryParseError implements IParseError {
    constructor(public name: string, public message: string, public partialTlv: ITlv[]) {}

    static errorPartialResult(error: Error, partialTlv: ITlv[]): TlvFactoryParseError{
        return new TlvFactoryParseError(error.name, error.message, partialTlv);
    }
}

class TlvFactoryTlvError implements Error {
    constructor(public name: string, public message: string) {}

    static errorEmpty(parameter: string): TlvFactoryTlvError {
        return new TlvFactoryTlvError('Error creating tlv item', '"' + parameter + '" must not be <null> or ""');
    }
    static errorUnevenBytes(parameter: string, given: string): TlvFactoryTlvError {
        return new TlvFactoryTlvError('Error creating tlv item', '"' + parameter + '" must be an even number, given "' + given + '"');
    }
    static errorContainsNonHex(parameter: string, given: string): TlvFactoryTlvError {
        return new TlvFactoryTlvError('Error creating tlv item', '"' + parameter + '" must only contain hex characters, given "' + given + '"');
    }
    static errorUnsupportedType(parameter: string): TlvFactoryTlvError {
        return new TlvFactoryTlvError('Error creating tlv item', '"' + parameter + '" is an unsupported format');
    }
}

class Tlv implements ITlv {
    public tag: string;
    public type: TlvType;
    public class: TlvClass;
    public items: ITlv[] | null;
    public value: Buffer | null;

    /**
     * Internal methods, no type checking done! Use at your own risk :)
     */
    constructor(tag: Buffer, payload?: Buffer | ITlv[]) {
        const tagBuffer: Buffer = tag;
        const tagString: string = tagBuffer.toString('hex').toUpperCase();;

        this.tag = tagString;
        this.type = TlvHelper.typeFromTag(tagBuffer);
        this.class = TlvHelper.classFromTag(tagBuffer);

        this.value = TlvFactoryHelper.verifyUncheckedTlvPrimitivePayload(this.type, payload);
        this.items = TlvFactoryHelper.verifyUncheckedTlvConstructedPayload(this.type, payload);
    }
}

export class TlvFactory {
    static primitiveTlv(tag: Buffer | string, value?: Buffer | string): ITlv {
        const verifiedTag: Buffer = TlvFactoryHelper.verifyGenericTag(tag);
        const verifiedValue: Buffer = TlvFactoryHelper.verifyPrimitiveValue(value);
        const primitiveTlv: ITlv = new Tlv(verifiedTag, verifiedValue);
        return primitiveTlv;
    }

    static constructedTlv(tag: Buffer | string, items?: ITlv | ITlv[]): ITlv {
        const verifiedTag: Buffer = TlvFactoryHelper.verifyGenericTag(tag);
        const verifiedItems: ITlv[] = TlvFactoryHelper.verifyConstructedItems(items);
        const constructedTlv: ITlv = new Tlv(verifiedTag, verifiedItems);
        return constructedTlv;
    }

    static parse(buffer: Buffer | string): ITlv[] {
        let verifiedValue;
        try {
            verifiedValue = TlvFactoryHelper.verifyParseValue(buffer);
        }
        catch(e: unknown){
            if (e instanceof TlvFactoryParseError)
                throw TlvFactoryParseError.errorPartialResult(e, []);
            throw e;
        }
        const parsedResult: TlvParserResult<ITlv[]> = TlvParser.parseItems(verifiedValue);
        if (parsedResult.error != null){
            throw TlvFactoryParseError.errorPartialResult(parsedResult.error, parsedResult.result);
        }
        return parsedResult.result;
    }

    static serialize(items: ITlv | ITlv[]): Buffer {
        const verifiedItems: ITlv[] = TlvFactoryHelper.verifySerializeItems(items);
        const serializedItems: Buffer = TlvSerializer.serializeItems(verifiedItems);
        return serializedItems;
    }

}

class TlvFactoryHelper {

    static verifyUncheckedTlvPrimitivePayload(type: TlvType, payload?: Buffer | ITlv[]): Buffer | null{
        if(type !== TlvType.PRIMITIVE){
            return null;
        }
        if (payload == null){
            return Buffer.alloc(0);
        }

        return <Buffer>payload;
    }

    static verifyUncheckedTlvConstructedPayload(type: TlvType, payload?: Buffer | ITlv[]): ITlv[] | null{
        if(type !== TlvType.CONSTRUCTED){
            return null;
        }
        if (payload == null){
            return [];
        }

        return <ITlv[]>payload;
    }


    static verifyGenericTag(tag: Buffer | string): Buffer {
        if (tag == null){
            throw TlvFactoryTlvError.errorEmpty('tag');
        }

        if (Buffer.isBuffer(tag)){
            return TlvFactoryHelper.fromBuffer(tag);
        }
        else if (typeof tag === 'string'){
            return TlvFactoryHelper.fromString('tag', tag);
        }
        else {
            throw TlvFactoryTlvError.errorUnsupportedType('tag');
        }
    }


    static verifyPrimitiveValue(buffer?: Buffer | string): Buffer {
        if (buffer == null){
            return TlvFactoryHelper.emptyBuffer();
        }
        else if (Buffer.isBuffer(buffer)){
            return TlvFactoryHelper.fromBuffer(buffer);
        }
        else if (typeof buffer === 'string'){
            return TlvFactoryHelper.fromString('value', buffer);
        }
        else {
            throw TlvFactoryTlvError.errorUnsupportedType('value');
        }
    }

    static verifyConstructedItems(items?: ITlv | ITlv[]): ITlv[] {
        if (items == null){
            return [];
        }
        else if (Array.isArray(items)){
            return items;
        }
        else {
            return [items];
        }
    }

    static verifyParseValue(buffer?: Buffer | string): Buffer {
        if (buffer == null){
            return  TlvFactoryHelper.emptyBuffer();
        }
        else if (Buffer.isBuffer(buffer)){
            return  TlvFactoryHelper.fromBuffer(buffer);
        }
        else if (typeof buffer === 'string'){
            return TlvFactoryHelper.fromString('value', buffer);
        }
        else {
            throw TlvFactoryTlvError.errorUnsupportedType('buffer');
        }
    }

    static verifySerializeItems(items: ITlv | ITlv[]): ITlv[] {
        if (items == null){
            throw TlvFactoryTlvError.errorUnsupportedType('items');
        }
        if (Array.isArray(items)){
            return items;
        }
        else {
            return [items];
        }
    }


    static emptyBuffer(): Buffer{
        return Buffer.alloc(0);
    }

    static fromBuffer(buffer: Buffer): Buffer {
        const verifiedBuffer: Buffer = buffer;
        return verifiedBuffer;
    }
    static fromString(parameter: string, string: string): Buffer {
        if (string.length % 2 !== 0){
            throw TlvFactoryTlvError.errorUnevenBytes(parameter, string);
        }

        try {
            string = string.toUpperCase();
            return Buffer.from(string, 'hex');
        }
        catch (error){
            throw TlvFactoryTlvError.errorContainsNonHex(parameter, string);
        }
    }

}
