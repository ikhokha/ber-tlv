import { expect } from 'chai';
import { ITlv, TlvType, TlvClass } from './Tlv';
import { TlvFactory } from './TlvFactory';

function tlvGenerator(tag: string, length:string, value: string): Buffer {
    const tagBuffer: Buffer = Buffer.from(tag.replace(' ', ''), 'hex');
    const lengthBuffer: Buffer = Buffer.from(length.replace(' ', ''), 'hex');
    const valueBuffer: Buffer = Buffer.from(value.replace(' ', ''), 'hex');
    return Buffer.concat([tagBuffer, lengthBuffer, valueBuffer]);
}

/**
 * Unit tests
 */
describe('TlvFactory', () => {

    describe('#parse', () => {

        it('can parse 1 byte tag primitve tlv object', () => {
            const buffer = tlvGenerator('005A', '02', '2020');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('5A');
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });
        it('can parse 2 byte tag primitve tlv object', () => {
            const buffer = tlvGenerator('9F02', '02', '2020');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('9F02');
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });
        it('can parse 3 byte tag primitve tlv object', () => {
            const buffer = tlvGenerator('DFAE03', '02', '2020');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('DFAE03');
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });

        it('can parse a constructed tlv object', () => {
            const buffer = tlvGenerator('E0', '08', '9A02AABB 9B02DDFF');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('E0');
            expect(item?.type).to.equal(TlvType.CONSTRUCTED);
        });

        it('can parse 1 byte tag with 1 byte length primitve tlv object', () => {
            const buffer = tlvGenerator('DFAE03', '8102', '2020');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('DFAE03');
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });
        it('can parse 1 byte tag with 2 byte length primitve tlv object', () => {
            const buffer = tlvGenerator('DFAE03', '820002', '2020');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('DFAE03');
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });
        it('can parse 1 byte tag with 3 byte length primitve tlv object', () => {
            const buffer = tlvGenerator('DFAE03', '83000002', '2020');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('DFAE03');
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });
        it('can parse 1 byte tag with 4 byte length primitve tlv object', () => {
            const buffer = tlvGenerator('DFAE03', '8400000002', '2020');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('DFAE03');
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });

        it('parses 0 length item', () => {
            const buffer = tlvGenerator('12', '00', '');
            const items = TlvFactory.parse(buffer);

            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('12');
            expect(item?.value).to.exist;
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });

        it('ignores 00 in between', () => {
            const buffer =  Buffer.from('00005A0101005702020200', 'hex');
            const items = TlvFactory.parse(buffer);

            expect(items.length).to.equal(2);
            expect(items).to.exist;
            const item: ITlv | undefined = items.pop()
            expect(item).not.to.be.undefined;
            expect(item?.tag).to.equal('57');
            expect(item?.value).to.exist;
            expect(item?.type).to.equal(TlvType.PRIMITIVE);
        });
        //ignores 00

        it('fails on empty data', () => {
            const buffer = tlvGenerator('DF', '', '');
            const throwFunction = () => {
                TlvFactory.parse(buffer);
            }

            expect(throwFunction).to.throw;
        });

    });

    describe('#primitiveTlv', () => {

        it('creates primitive with <string>(uppercase)', () => {
            const givenTagString = '5A';
            const givenValueString = '90DF';
            const expectedBuffer = Buffer.from('5A0290DF', 'hex');

            const tlv = TlvFactory.primitiveTlv(givenTagString, givenValueString);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates primitive with <string>(lowercase)', () => {
            const givenTagString = '5a';
            const givenValueString = '90df';
            const expectedBuffer = Buffer.from('5A0290DF', 'hex');

            const tlv = TlvFactory.primitiveTlv(givenTagString, givenValueString);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates primitive with <Buffer>', () => {
            const givenTagBuffer = Buffer.from('5A', 'hex');
            const givenValueBuffer = Buffer.from('90DF', 'hex');
            const expectedBuffer = Buffer.from('5A0290DF', 'hex');

            const tlv = TlvFactory.primitiveTlv(givenTagBuffer, givenValueBuffer);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates primitive with <Buffer>, <string>', () => {
            const givenTagBuffer = Buffer.from('5A', 'hex');
            const givenValueString = '90df';
            const expectedBuffer = Buffer.from('5A0290DF', 'hex');

            const tlv = TlvFactory.primitiveTlv(givenTagBuffer, givenValueString);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates primitive with <string>, buffer', () => {
            const givenTagString = '5a';
            const givenValueBuffer = Buffer.from('90DF', 'hex');
            const expectedBuffer = Buffer.from('5A0290DF', 'hex');

            const tlv = TlvFactory.primitiveTlv(givenTagString, givenValueBuffer);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates primitive with no value', () => {
            const givenTagString = '5A';
            const expectedBuffer = Buffer.from('5A00', 'hex');

            const tlv = TlvFactory.primitiveTlv(givenTagString);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('fails with invalid tag class', () => {
            const givenTagString = 'E0';

            const throwFunction = () => {
                TlvFactory.primitiveTlv(givenTagString);
            }

            expect(throwFunction).to.throw;
        });

        it('fails with invalid data (tag)', () => {
            const givenNumber = 22;

            const throwFunction = () => {
                TlvFactory.primitiveTlv(<any>givenNumber, '');
            }

            expect(throwFunction).to.throw;
        });

        it('fails with invalid data (value)', () => {
            const givenNumber = 22;

            const throwFunction = () => {
                TlvFactory.primitiveTlv('', <any>givenNumber);
            }

            expect(throwFunction).to.throw;
        });


    });

    describe('#constructedTlv', () => {

        it('creates constrcuted with <string>(uppercase)', () => {
            const givenTagString = 'E0';
            const givenPayloadTlv = TlvFactory.parse("5A00");
            const expectedBuffer = Buffer.from('E0025A00', 'hex');

            const tlv = TlvFactory.constructedTlv(givenTagString, givenPayloadTlv);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates constructed with <string>(lowercase)', () => {
            const givenTagString = 'e0';
            const givenPayloadTlv = TlvFactory.parse("5A00");
            const expectedBuffer = Buffer.from('E0025A00', 'hex');

            const tlv = TlvFactory.constructedTlv(givenTagString, givenPayloadTlv);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates constructed with <buffer>', () => {
            const givenTagBuffer = Buffer.from('E0', 'hex');
            const givenPayloadTlv = TlvFactory.parse("5A00");
            const expectedBuffer = Buffer.from('E0025A00', 'hex');

            const tlv = TlvFactory.constructedTlv(givenTagBuffer, givenPayloadTlv);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates constructed with no payload', () => {
            const givenTagBuffer = Buffer.from('E0', 'hex');
            const expectedBuffer = Buffer.from('E000', 'hex');

            const tlv = TlvFactory.constructedTlv(givenTagBuffer);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates constructed with array payload', () => {
            const givenTagBuffer = Buffer.from('E0', 'hex');
            const givenPayloadTlv = TlvFactory.parse("5A00");
            const expectedBuffer = Buffer.from('E0025A00', 'hex');

            const tlv = TlvFactory.constructedTlv(givenTagBuffer, givenPayloadTlv);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('creates constructed with single payload', () => {
            const givenTagBuffer = Buffer.from('E0', 'hex');
            const givenPayloadTlv = TlvFactory.primitiveTlv("5A");
            const expectedBuffer = Buffer.from('E0025A00', 'hex');

            const tlv = TlvFactory.constructedTlv(givenTagBuffer, givenPayloadTlv);
            const serialized = TlvFactory.serialize(tlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('fails with invalid payload', () => {
            const givenTagString = '5a';
            const givenValueNumber = 22;

            const throwFunction = () => {
                TlvFactory.primitiveTlv(givenTagString, <any>givenValueNumber);
            }

            expect(throwFunction).to.throw;
        });

        it('fails with invalid tag class', () => {
            const givenTagString = '5A';

            const throwFunction = () => {
                TlvFactory.constructedTlv(givenTagString);
            }

            expect(throwFunction).to.throw;
        });

        it('fails with invalid data (tag)', () => {
            const givenNumber: number = 22;

            const throwFunction = () => {
                TlvFactory.constructedTlv(<any>givenNumber, []);
            }

            expect(throwFunction).to.throw;
        });

        it('fails with invalid data (value)', () => {
            const givenNumber: number = 22;

            const throwFunction = () => {
                TlvFactory.primitiveTlv('', <any>givenNumber);
            }

            expect(throwFunction).to.throw;
        });


    });

    describe('#serialize', () => {

        it('serializes primitive', () => {
            const givenTlv = TlvFactory.primitiveTlv('5A', '0100')
            const expectedBuffer = tlvGenerator('5A', '02', '0100');

            const serialized = TlvFactory.serialize(givenTlv);

            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('serializes concatenated primitive', () => {
            const givenTlv = TlvFactory.parse('5A020100570101')
            const expectedBuffer = Buffer.concat([tlvGenerator('5A', '02', '0100'), tlvGenerator('57', '01', '01')]);

            const serialized = TlvFactory.serialize(givenTlv);

            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('serializes constructed', () => {
            const givenTlv = TlvFactory.constructedTlv('E0', TlvFactory.primitiveTlv('57'))
            const expectedBuffer = tlvGenerator('E0', '02', '5700');

            const serialized = TlvFactory.serialize(givenTlv);

            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('serializes concatenated constructed', () => {
            const givenTlv = TlvFactory.parse('E0025700E0055A01015700')
            const expectedBuffer = Buffer.concat([tlvGenerator('E0', '02', '5700'), tlvGenerator('E0', '05', '5A01015700')]);

            const serialized = TlvFactory.serialize(givenTlv);

            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });

        it('serializes constructed constructed', () => {
            const givenTlv = TlvFactory.parse('E005E003570101')
            const expectedBuffer = tlvGenerator('E0', '05', 'E003570101');

            const serialized = TlvFactory.serialize(givenTlv);
            expect(serialized.toString('hex')).to.equal(expectedBuffer.toString('hex'));
        });


        it('fails on wrong data', () => {
            const buffer = Buffer.alloc(0);
            const throwFunction = () => {
                TlvFactory.serialize(<any>buffer);
            }

            expect(throwFunction).to.throw;
        });

    });

});

describe('Tlv', () => {

    describe('#class', () => {

        it('identified universal', () => {
        const tlv = TlvFactory.primitiveTlv('0F', Buffer.alloc(0));
          expect(tlv.class).to.equal(TlvClass.UNIVERSAL);
        });
        it('identified application', () => {
        const tlv = TlvFactory.primitiveTlv('4F', Buffer.alloc(0));
          expect(tlv.class).to.equal(TlvClass.APPLICATION);
        });
        it('identified context-specific', () => {
        const tlv = TlvFactory.primitiveTlv('8F', Buffer.alloc(0));
          expect(tlv.class).to.equal(TlvClass.CONTEXT_SPECIFIC);
        });
        it('identified private', () => {
          const tlv = TlvFactory.primitiveTlv('CF', Buffer.alloc(0));
          expect(tlv.class).to.equal(TlvClass.PRIVATE);
        });

    });

    describe('#type', () => {

        it('identified primitive', () => {
          const tlv = TlvFactory.primitiveTlv('5A', Buffer.alloc(0));
          expect(tlv.type).to.equal(TlvType.PRIMITIVE);
        });
        it('identified constructed', () => {
          const tlv = TlvFactory.primitiveTlv('E0', Buffer.alloc(0));
          expect(tlv.type).to.equal(TlvType.CONSTRUCTED);
        });
    });
});
