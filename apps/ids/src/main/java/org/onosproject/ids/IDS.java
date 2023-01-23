package org.onosproject.ids;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import org.onlab.packet.BasePacket;
import org.onlab.packet.Deserializer;

import java.nio.ByteBuffer;

import static org.onlab.packet.PacketUtils.checkInput;

public class IDS  extends BasePacket {

    public static final short HW_TYPE_ETHERNET = 0x1742;
    public static final short IDS_HEADER_LENGTH = 105; // bytes

    protected byte type;
    protected int regIndex;
    protected int centroidNormalBytes;
    protected int centroidNormalPackets;
    protected int centroidAbNormalBytes;
    protected int centroidAbNormalPackets;

    protected int redundant1 = 0;
    protected long redundant2 = 0;
    protected int redundant3 = 0;
    protected long redundant4 = 0;
    protected long redundant5 = 0;
    protected int redundant6 = 0;
    protected long redundant7 = 0;
    protected int redundant8 = 0;
    protected long redundant9 = 0;
    protected long redundant10 = 0;

    protected int srcAddress = 0;
    protected int dstAddress = 0;
    protected short srcPort = 0;
    protected short dstPort = 0;

    public enum IdsType {
        INIT((byte)1), RESUBMIT((byte)2);

        private byte value;

        IdsType(byte value) {
            this.value = value;
        }

        public byte getValue() {
            return value;
        }
    }

    public byte getType() {
        return type;
    }

    public IDS setType(final byte type) {
        this.type = type;
        return this;
    }

    public int getRegIndex() {
        return regIndex;
    }

    public IDS setRegIndex(final int regIndex) {
        this.regIndex = regIndex;
        return this;
    }

    public int getCentroidNormalBytes() {
        return centroidNormalBytes;
    }

    public IDS setCentroidNormalBytes(final int centroidNormalBytes) {
        this.centroidNormalBytes = centroidNormalBytes;
        return this;
    }

    public int getCentroidAbNormalBytes() {
        return centroidAbNormalBytes;
    }

    public IDS setCentroidAbNormalBytes(final int centroidAbNormalBytes) {
        this.centroidAbNormalBytes = centroidAbNormalBytes;
        return this;
    }

    public int getCentroidNormalPackets() {
        return centroidNormalPackets;
    }

    public IDS setCentroidNormalPackets(int centroidNormalPackets) {
        this.centroidNormalPackets = centroidNormalPackets;
        return this;
    }

    public int getCentroidAbNormalPackets() {
        return centroidAbNormalPackets;
    }

    public IDS setCentroidAbNormalPackets(int centroidAbNormalPackets) {
        this.centroidAbNormalPackets = centroidAbNormalPackets;
        return this;
    }

    @Override
    public byte[] serialize() {
        final byte[] data = new byte[IDS_HEADER_LENGTH];
        final ByteBuffer bb = ByteBuffer.wrap(data);
        //put type
        bb.put(type);
        //put ids index as zero
        bb.putInt(regIndex);
        //put centroid normal for packet amount
        bb.putInt(centroidNormalBytes);
        //put centroid normal for packet bytes
        bb.putInt(centroidNormalPackets);
        //put centroid abnormal for packet amount
        bb.putInt(centroidAbNormalBytes);
        //put centroid abnormal for packet bytes
        bb.putInt(centroidAbNormalPackets);
        //put redundant fields
        bb.putInt(redundant1);
        bb.putLong(redundant2);
        bb.putInt(redundant3);
        bb.putLong(redundant4);
        bb.putLong(redundant5);
        bb.putInt(redundant6);
        bb.putLong(redundant7);
        bb.putInt(redundant8);
        bb.putLong(redundant9);
        bb.putLong(redundant10);

        bb.putInt(srcAddress);
        bb.putInt(dstAddress);
        bb.putShort(srcPort);
        bb.putShort(dstPort);
        return data;
    }

    public static Deserializer<IDS> deserializer() {
        return (data, offset, length) -> {
            checkInput(data, offset, length, IDS_HEADER_LENGTH);

            IDS ids = new IDS();
            final ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
            ids.setType(bb.get());
            ids.setRegIndex(bb.getInt());
            ids.setCentroidNormalBytes(bb.getInt());
            ids.setCentroidNormalPackets(bb.getInt());
            ids.setCentroidAbNormalBytes(bb.getInt());
            ids.setCentroidAbNormalPackets(bb.getInt());
            return ids;
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof IDS)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        IDS ids = (IDS) o;
        return getType() == ids.getType() &&
                getRegIndex() == ids.getRegIndex() &&
                getCentroidNormalBytes() == ids.getCentroidNormalBytes() &&
                getCentroidNormalPackets() == ids.getCentroidNormalPackets() &&
                getCentroidAbNormalBytes() == ids.getCentroidAbNormalBytes() &&
                getCentroidAbNormalPackets() == ids.getCentroidAbNormalPackets();
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(super.hashCode(), getType(), getRegIndex(), getCentroidNormalBytes(), getCentroidNormalPackets(),
                                getCentroidAbNormalBytes(), getCentroidAbNormalPackets());
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("type", Byte.toString(type))
                .add("regIndex", Integer.toString(regIndex))
                .add("centroidNormal", Integer.toString(centroidNormalBytes))
                .add("centroidNormalBytes", Integer.toString(centroidNormalPackets))
                .add("centroidAbNormal", Integer.toString(centroidAbNormalBytes))
                .add("centroidAbNormalBytes", Integer.toString(centroidAbNormalPackets))
                .toString();
    }
}
