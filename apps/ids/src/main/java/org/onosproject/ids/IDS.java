package org.onosproject.ids;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import org.onlab.packet.BasePacket;
import org.onlab.packet.Deserializer;

import java.nio.ByteBuffer;

import static org.onlab.packet.PacketUtils.checkInput;

public class IDS  extends BasePacket {

    public static final short HW_TYPE_ETHERNET = 0x1742;
    public static final short IDS_HEADER_LENGTH = 13; // bytes

    protected byte type;
    protected int regIndex;
    protected int centroidNormal;
    protected int centroidAbNormal;

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

    public int getCentroidNormal() {
        return centroidNormal;
    }

    public IDS setCentroidNormal(final int centroidNormal) {
        this.centroidNormal = centroidNormal;
        return this;
    }

    public int getCentroidAbNormal() {
        return centroidAbNormal;
    }

    public IDS setCentroidAbNormal(final int centroidAbNormal) {
        this.centroidAbNormal = centroidAbNormal;
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
        //put centroid normal
        bb.putInt(centroidNormal);
        //put centroid abnormal
        bb.putInt(centroidAbNormal);
        return data;
    }

    public static Deserializer<IDS> deserializer() {
        return (data, offset, length) -> {
            checkInput(data, offset, length, IDS_HEADER_LENGTH);

            IDS ids = new IDS();
            final ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
            ids.setType(bb.get());
            ids.setRegIndex(bb.getInt());
            ids.setCentroidNormal(bb.getInt());
            ids.setCentroidAbNormal(bb.getInt());
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
                getCentroidNormal() == ids.getCentroidNormal() &&
                getCentroidAbNormal() == ids.getCentroidAbNormal();
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(super.hashCode(), getType(), getRegIndex(), getCentroidNormal(), getCentroidAbNormal());
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("type", Byte.toString(type))
                .add("regIndex", Integer.toString(regIndex))
                .add("centroidNormal", Integer.toString(centroidNormal))
                .add("centroidAbNormal", Integer.toString(centroidAbNormal))
                .toString();
    }
}
