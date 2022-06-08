package org.onosproject.ids;

import com.google.common.collect.Maps;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.onosproject.ids.OsgiPropertyConstants.*;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * IDS application.
 */
@Component(
        immediate = true,
        service = IdsManager.class,
        property = {
                INIT + ":Boolean=" + INIT_DEFAULT,
                DEV + ":String=" + DEV_DEFAULT,
                PORT + ":Integer=" + PORT_DEFAULT,
                RESUBMIT_PERIOD + ":Integer=" + RESUBMIT_PERIOD_DEFAULT
        }
)
public class IdsManager {

    private final Logger log = getLogger(getClass());

    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    private boolean init = false;
    private String dev = "device:s172";
    private int port = 1;
    private int period = RESUBMIT_PERIOD_DEFAULT;

    private final ScheduledExecutorService scheduledExecutorService =
            Executors.newScheduledThreadPool(1);

    private DeviceListener deviceListener = new InternalDeviceListener();

    private ConcurrentMap<DeviceId, Counter> resubmitStatusMap = Maps.newConcurrentMap();

    private static final MacAddress SRC_MAC = MacAddress.valueOf("00:28:f8:83:69:ea");
    private static final MacAddress DST_MAC = MacAddress.valueOf("d2:5e:d3:d0:a5:15");

    @Activate
    public void activate(ComponentContext context) {
        appId = coreService.registerApplication("org.onosproject.ids");
        deviceService.addListener(deviceListener);
        cfgService.registerProperties(getClass());
        scheduledExecutorService.scheduleAtFixedRate(new ResubmitTask(), 1000, 1000, TimeUnit.MILLISECONDS);
        log.info("Started", appId.id());
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
    }

    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();

        Boolean initEnabled =
                Tools.isPropertyEnabled(properties, INIT);
        if (initEnabled != null) {
            log.info("Configured. Init is {}",
                     initEnabled ? "enabled" : "disabled");
            init = initEnabled;
            if (init) {
                senIdsInit(DeviceId.deviceId(dev), PortNumber.portNumber(port));
            }
        }
        port = Tools.getIntegerProperty(properties, PORT, PORT_DEFAULT);
        log.info("port configured to {}", port);

        String devStr = Tools.get(properties, DEV);
        if (devStr != null) {
            dev = devStr;
            log.info("dev configured to {}", dev);
        }

        period = Tools.getIntegerProperty(properties, RESUBMIT_PERIOD, RESUBMIT_PERIOD_DEFAULT);
        log.info("period configured to {}", period);
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_AVAILABILITY_CHANGED:
                    Device device = event.subject();
                    if (deviceService.isAvailable(device.id())) {
                        log.info("device {} become available to send IDSInit", device.id());
                        senIdsInit(device.id(), PortNumber.portNumber(1l));

                        resubmitStatusMap.putIfAbsent(device.id(), new Counter());
                        log.info("Resubmit counter started for device {}", device.id());
                    } else {
                        log.info("device {} become unavailable, resubmit counter is being removed from the cache", device.id());
                        resubmitStatusMap.remove(device.id());
                    }
                    break;
                default:
                    break;
            }
        }
    }

    public void senIdsInit(DeviceId deviceId, PortNumber portNumber) {
        if (!deviceService.isAvailable(deviceId)) {
            log.info("{} not available", deviceId);
            return;
        }
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().
                setOutput(portNumber).build();

        Ethernet eth = buildIdsInitEthernet();

        log.info("emitting IDSInit to dev {}/{}. eth:{}", deviceId, portNumber, eth);
        byte[] serialize = eth.serialize();

        log.info("serialized IDSInit length:{} hex:{}", serialize.length, toHex(serialize));

        OutboundPacket packet = new DefaultOutboundPacket(deviceId,
                                                          treatment, ByteBuffer.wrap(serialize));
        packetService.emit(packet);
        log.info("packet emitted");
    }

    public void senIdsResubmit(DeviceId deviceId) {
        if (!deviceService.isAvailable(deviceId)) {
            log.info("{} not available", deviceId);
            return;
        }
        PortNumber portNumber = PortNumber.portNumber(1);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().
                setOutput(portNumber).build();
        Ethernet eth = buildIdsResubmitEthernet();
        log.info("emitting IDSResubmit to dev {}/{}. eth:{}", deviceId, portNumber, eth);

        byte[] serialize = eth.serialize();
        log.info("serialized IDSResubmit length:{} hex:{}", serialize.length, toHex(serialize));

        OutboundPacket packet = new DefaultOutboundPacket(deviceId,
                                                          treatment, ByteBuffer.wrap(serialize));
        packetService.emit(packet);
        log.info("packet emitted");
    }

    private Ethernet buildIdsInitEthernet() {
        Ethernet ethernet = new Ethernet();
        Short etherType = (short) (IDS.HW_TYPE_ETHERNET & 0xFFFF);
        ethernet.setEtherType(etherType);
        ethernet.setSourceMACAddress(SRC_MAC);
        ethernet.setDestinationMACAddress(DST_MAC);

        IDS ids = new IDS();
        ids.setParent(ethernet);
        ids.setType(IDS.IdsType.INIT.getValue());
        ids.setRegIndex(0);
        ids.setCentroidNormal(1234);
        ids.setCentroidAbNormal(567890);
        ethernet.setPayload(ids);

        return ethernet;
    }

    private Ethernet buildIdsResubmitEthernet() {
        Ethernet ethernet = new Ethernet();
        Short etherType = (short) (IDS.HW_TYPE_ETHERNET & 0xFFFF);
        ethernet.setEtherType(etherType);
        ethernet.setSourceMACAddress(SRC_MAC);
        ethernet.setDestinationMACAddress(DST_MAC);

        IDS ids = new IDS();
        ids.setParent(ethernet);
        ids.setType(IDS.IdsType.RESUBMIT.getValue());
        ids.setRegIndex(0);
        ids.setCentroidNormal(0);
        ids.setCentroidAbNormal(0);
        ethernet.setPayload(ids);

        return ethernet;
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    private String toBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(Integer.toBinaryString(b & 255 | 256).substring(1));
            sb.append("\n");
        }
        return sb.toString();
    }

    private class Counter {
        private final AtomicInteger counter = new AtomicInteger(0);

        public int increaseAndGetCounter() {
            return this.counter.addAndGet(1);
        }

        public int getCounter() {
            return this.counter.get();
        }

        public void resetCounter() {
            this.counter.set(0);
        }
    }

    private class ResubmitTask extends TimerTask {
        @Override
        public void run() {
            log.debug("resubmit task is awake");
            //check device counters
            for (DeviceId deviceId:resubmitStatusMap.keySet()) {
                Counter counter = resubmitStatusMap.get(deviceId);
                if (counter == null) {
                    continue;
                }
                int currentValue = counter.increaseAndGetCounter();
                log.info("{} counter is {}", deviceId, currentValue);
                if (currentValue >= period) {
                    //Send message
                    senIdsResubmit(deviceId);
                    counter.resetCounter();
                }
                resubmitStatusMap.put(deviceId, counter);
            }
        }
    }
}
