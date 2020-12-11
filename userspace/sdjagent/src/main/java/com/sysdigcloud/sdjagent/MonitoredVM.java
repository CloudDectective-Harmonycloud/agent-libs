/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sysdigcloud.sdjagent;

import com.fasterxml.jackson.databind.ObjectMapper;
import sun.jvmstat.monitor.MonitorException;

import javax.management.*;
import java.io.*;
import java.util.*;
import java.util.logging.Logger;

/**
 *
 * @author Luca Marturana <luca@draios.com>
 */
public class MonitoredVM {
    private static final Logger LOGGER = Logger.getLogger(MonitoredVM.class.getName());
    private static final long BEAN_REFRESH_INTERVAL = 10 * 60 * 1000; // 10 minutes in ms
    private static final long RECONNECTION_TIMEOUT_MS = 1 * 60 * 1000; // 1 minute
    private int beansLimit = 300;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /**
     * Default hostname used to connect to JMX, "localhost" does not play well with containers
     */
    private static final String DEFAULT_LOCALHOST = "127.0.0.1";
    private String address;
    private Connection connection;
    private final int pid;
    private String name;
    /**
     * Available means that we can get at least the mainClass from target JVM
     */
    private boolean available;
    private long lastBeanRefresh;
    private final List<Config.BeanQuery> queryList;
    private final List<BeanInstance> matchingBeans;
    private long lastDisconnectionTimestamp;
    private final boolean isOnAnotherContainer;
    private CheckForAvailabilityTimer checkForAvailabilityTimer;

    private class CheckForAvailabilityTimer {
        private long nextCheckMs;
        private long checkCounter;
        private static final int MS = 1000;
        private long maxAvailabilityCheckIntervalMs;
        private boolean maxReached;
        private static final int RANDOM_INTERVAL_SEC = 30;
        int initialRandomDelayMs;

        CheckForAvailabilityTimer() {
            reset();
        }

        void setMaxCheckForAvailabilityIntervalSec(int d) {
            maxAvailabilityCheckIntervalMs = d * MS;
        }

        boolean isTimeForCheck() {
            boolean ret = false;
            long now = System.currentTimeMillis();

            if(nextCheckMs == 0 || now > nextCheckMs){
                ret = true;

                if (nextCheckMs == 0) {
                    // if this is the very first check, schedule the next one on a random point in time
                    // This will avoid to check many VMs in the same time
                    Random rand = new Random();

                    // initialRandomDelay is a random value between 5 secs and RANDOM_INTERNAL_SEC secs
                    initialRandomDelayMs = (5 + rand.nextInt(RANDOM_INTERVAL_SEC - 5)) * MS;
                    nextCheckMs = now + initialRandomDelayMs;
                } else if (!maxReached) {
                    // double the interval for retrying every cycle. Till the maximum interval is reached
                    nextCheckMs = (long) (now + Math.pow(2, checkCounter++)*MS + initialRandomDelayMs);
                    // do not overcome max interval time
                    if ((nextCheckMs - now) >= maxAvailabilityCheckIntervalMs) {
                        maxReached = true;
                        nextCheckMs = now + maxAvailabilityCheckIntervalMs;
                    }
                } else {
                    // already reached the maximum interval
                    nextCheckMs = now + maxAvailabilityCheckIntervalMs;
                }
            }

            return ret;
        }

        private void reset() {
            this.nextCheckMs = 0;
            this.checkCounter = 0;
            this.maxReached = false;
        }
    }
    public MonitoredVM(VMRequest request)
    {
        this.pid = request.getPid();
        this.queryList = new ArrayList<Config.BeanQuery>();
        this.lastBeanRefresh = 0;
        this.matchingBeans = new ArrayList<BeanInstance>();
        this.available = false;
        //this.agentActive = false;
        this.name = "";
        this.lastDisconnectionTimestamp = 0;
        this.checkForAvailabilityTimer = new CheckForAvailabilityTimer();

        if (request.getPid() == CLibrary.getPid()) {
            this.name = "sdjagent";
            available = true;
            isOnAnotherContainer = false;
            return;
        }

        isOnAnotherContainer = CLibrary.isOnAnotherContainer(request.getPid());
        checkForAvailability(request);
    }

    public void setMaxavailabilityCheckIntervalSec(int d) {
        checkForAvailabilityTimer.setMaxCheckForAvailabilityIntervalSec(d);
    }

    public boolean checkForAvailability(VMRequest request) {
        if (available == false) {
            if (checkForAvailabilityTimer.isTimeForCheck()) {
                if (isOnAnotherContainer) {
                    retrieveVmInfoFromContainer(request);
                } else {
                    retrieveVMInfoFromHost(request);
                }
                if (!this.available && (request.getArgs().length > 0)) {
                    // This way is faster but it's more error prone
                    // so keep it as last chance
                    retrieveVMInfoFromArgs(request);
                }
            }
        }
        return available;
    }

    private void retrieveVmInfoFromContainer(VMRequest request) {
        String data = null;

        // Try to get jvm data from jni without running sdjagent in the container
        data = CLibrary.getJMXAddressFromContainer(request.getPid(), request.getVpid());

        // backup to copy into container
        if(data == null) {
            LOGGER.info(String.format("Unable to get jmx address (%d,%d) from JNI. Trying to copy and run sdjagent on the app container",
                    request.getPid(), request.getVpid()));
            final String sdjagentPath = String.format("%s/tmp/sdjagent.jar", request.getRoot());
            LOGGER.fine(String.format("Copying sdjagent jar to %s", sdjagentPath));
            if (CLibrary.copyToContainer(Prefix.getInstallPrefix() + "/share/sdjagent.jar", request.getPid(), sdjagentPath)) {
                final String[] command = {"java", "-Dsdjagent.loadjnilibrary=false", "-jar", "/tmp/sdjagent.jar", "reenter",
                                                    String.valueOf(request.getVpid()), String.valueOf(request.getPid())};
                // Using /proc/<pid>/exe because sometimes java command is not on PATH
                final String javaExe = String.format("/proc/%d/exe", request.getVpid());
                data = CLibrary.runOnContainer(request.getPid(), request.getVpid(), javaExe, command, request.getRoot());
            } else {
                // These logs are with debug priority because may happen for every short lived java process
                LOGGER.fine(String.format("Cannot copy sdjagent files on container for pid (%d:%d)", request.getPid(),
                        request.getVpid()));
            }
            CLibrary.rmFromContainer(request.getPid(), sdjagentPath);
        }

        if (data != null && !data.isEmpty())
        {
            try {
                final Map<String, Object> vmInfo = MAPPER.readValue(data, Map.class);
                if (vmInfo.containsKey("available")) {
                    this.available = (Boolean)vmInfo.get("available");
                    if (vmInfo.containsKey("name")) {
                        this.name = (String)vmInfo.get("name");
                    }
                    if (vmInfo.containsKey("address")) {
                        this.address = (String)vmInfo.get("address");
                    }
                }
            } catch (IOException ex) {
                LOGGER.severe(String.format("Wrong data from getVMHandle for process (%d:%d): %s, exception: %s",
                        request.getPid(), request.getVpid(), data, ex.getMessage()));
            }
        }
        else
        {
            LOGGER.fine(String.format("No data from getVMHandle for process (%d:%d)", request.getPid(), request
                    .getVpid()));
        }
    }

    private void retrieveVMInfoFromHost(VMRequest request) {
        // To load the agent, we need to be the same user and group
        // of the process
        boolean uidChanged = false;
        if(!request.skipUidAndGid()) {
            try {
                long[] idInfo = CLibrary.getUidAndGid(request.getPid());
                int gid_error = CLibrary.setegid(idInfo[1]);
                int uid_error = CLibrary.seteuid(idInfo[0]);
                if (uid_error == 0 && gid_error == 0) {
                    LOGGER.fine(String.format("Change uid and gid to %d:%d", idInfo[0], idInfo[1]));
                } else {
                    LOGGER.warning(String.format("Cannot change uid and gid to %d:%d, errors: %d:%d (pid=%d vpid=%d root=%s args=%s)",
                                   idInfo[0], idInfo[1], uid_error, gid_error, request.getPid(), request.getVpid(), request.getRoot(), Arrays.toString(request.getArgs())));
                }
                uidChanged = true;
            } catch (IOException ex)
            {
                LOGGER.warning(String.format("Cannot read uid:gid data from process %d: %s (vpid=%d root=%s args=%s)",
                               pid, ex.getMessage(), request.getVpid(), request.getRoot(), Arrays.toString(request.getArgs())));
            }
        }

        try {
            JvmstatVM jvmstat;
            jvmstat = new JvmstatVM(request.getPid());
            this.name = jvmstat.getMainClass();
            // Try to get local address from jvmstat
            this.address = jvmstat.getJMXAddress();
            jvmstat.detach();
	    if (this.address != null) {
                available = true;
	    }
        } catch (MonitorException e) {
            LOGGER.warning(String.format("JvmstatVM cannot attach to process %d: %s (vpid=%d root=%s args=%s)",
                           this.pid, e.getMessage(), request.getVpid(), request.getRoot(), Arrays.toString(request.getArgs())));
            return;
        }

        // Try to load agent and get address from there
        if (this.address == null)
        {
            try
            {
                this.address = AttachAPI.loadManagementAgent(request.getPid());
            } catch (IOException e)
            {
                LOGGER.warning(String.format("Cannot load agent on process %d: %s (vpid=%d root=%s args=%s)",
                               this.pid, e.getMessage(), request.getVpid(), request.getRoot(), Arrays.toString(request.getArgs())));
            }
        }

        if (uidChanged)
        {
            // Restore to uid and gid to root
            int uid_error = CLibrary.seteuid(0);
            int gid_error = CLibrary.setegid(0);
            if (uid_error == 0 && gid_error == 0) {
                LOGGER.fine("Restore uid and gid");
            } else {
                LOGGER.severe(String.format("Cannot restore uid and gid, errors: %d:%d (pid=%d vpid=%d root=%s args=%s)",
                              uid_error, gid_error, request.getPid(), request.getVpid(), request.getRoot(), Arrays.toString(request.getArgs())));
            }
        }
    }

    private void retrieveVMInfoFromArgs(VMRequest request) {
        int port = -1;
        String hostname = DEFAULT_LOCALHOST;
        boolean authenticate = false;
        String name = null;
        for(String arg : request.getArgs()) {
            if (arg.startsWith("-Dcom.sun.management.jmxremote.port=")) { // NOI18N
                port = Integer.parseInt(arg.substring(arg.indexOf("=") + 1)); // NOI18N
            } else if (arg.equals("-Dcom.sun.management.jmxremote.authenticate=true")) { // NOI18N
                LOGGER.warning(String.format("Process with pid %d has JMX active but requires authorization, please disable it", request.getPid()));
                authenticate = true;
            } else if (arg.startsWith("-Dcom.sun.management.jmxremote.host=")) {
                hostname = arg.substring(arg.indexOf("=") + 1);
            } else if (arg.startsWith("-Dcassandra.jmx.local.port=")) { // Hack to autodetect cassandra
                port = Integer.parseInt(arg.substring(arg.indexOf("=") + 1));
                name = "org.apache.cassandra.service.CassandraDaemon"; // To avoid false negatives force cassandra here
            } else if (arg.startsWith("-jar:")){
                name = arg.substring("-jar:".length());
            }
        }
        if (port != -1 && authenticate == false) {
            if(name != null) {
                this.name = name;
            } else if(request.getArgs().length > 0) {
                // Assume the last arg is the main class, gross assumption but
                // we don't have better ways at this point
                this.name = request.getArgs()[request.getArgs().length-1];
            } else {
                this.name = "unknown";
            }
            this.address = String.format("service:jmx:rmi:///jndi/rmi://%s:%d/jmxrmi", hostname, port);
            this.available = true;
        }

        LOGGER.info(String.format("JVM pid=%d vpid=%d info from args: hostname=%s port=%d authenticate=%s name=%s (args=%s)",
                                  request.getPid(), request.getVpid(), hostname, port, authenticate, this.name, Arrays.toString(request.getArgs())));
    }

    public boolean isAvailable() {
        return available;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String value)
    {
        this.name = value;
    }

    public String getAddress() {
        return address;
    }

    public void setBeansLimit(int beansLimit) {
        this.beansLimit = beansLimit;
    }

    public void addQueries(List<Config.BeanQuery> queries) {
        queryList.addAll(queries);
    }

    private void refreshMatchingBeans() throws IOException {
        matchingBeans.clear();
        Set<ObjectName> allBeans = connection.getMbs().queryNames(null, null);
        for (ObjectName bean : allBeans) {
            for( Config.BeanQuery query : queryList) {
                if (query.getObjectName().apply(bean)) {
                    matchingBeans.add(new BeanInstance(bean,query.getAttributes()));
                }
            }
            if (matchingBeans.size() >= beansLimit) {
                LOGGER.warning(String.format("Hit bean limit (%d) for process %d (%s), ignoring further beans", beansLimit, pid, name));
                break;
            }
        }
        LOGGER.fine(String.format("Got %d/%d beans for process %d (%s)", matchingBeans.size(), beansLimit, pid, name));
    }

    public List<Map<String, Object>> availableMetrics(boolean all) throws IOException {
        setNetworkNamespaceIfNeeded();
        if (connection == null) {
            Tracer trc = new Tracer("createConnection");
            trc.enter(null);
            connection = new Connection(this.address);
            trc.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("isAlive", Boolean.toString(connection.isAlive())))));
        }
        final Set<ObjectName> allBeans = connection.getMbs().queryNames(null, null);
        final List<Map<String, Object>> availableMetrics = new ArrayList<Map<String, Object>>(allBeans.size());
        for (final ObjectName bean : allBeans) {
            try {
                final Map<String, Object> beanData = new HashMap<String, Object>();
                beanData.put("query", bean.getCanonicalName());
                final MBeanInfo beanInfo = connection.getMbs().getMBeanInfo(bean);
                final MBeanAttributeInfo[] attributeInfos = beanInfo.getAttributes();
                final List<Object> attributes = new ArrayList<Object>(attributeInfos.length);
                for(int j = 0; j < attributeInfos.length; ++j) {
                    final MBeanAttributeInfo attributeInfo = attributeInfos[j];

                    if (all) {
                        final Map<String, String> attributeData = new HashMap<String, String>();
                        attributeData.put("name", attributeInfo.getName());
                        attributeData.put("javaType", attributeInfo.getType());
                        try {
                            final String value = connection.getMbs().getAttribute(bean, attributeInfo.getName()).toString();
                            attributeData.put("value", value.substring(0,100));
                        } catch (Throwable e) {
                        }
                        attributes.add(attributeData);
                    }
                    else {
                        try {
                            final Object valueObj = connection.getMbs().getAttribute(bean, attributeInfo.getName());
                            BeanData.parseValueAsDouble(valueObj);
                            // The above function will throw if it's not able to convert the Object
                            // to a number so the following line will not be executed
                            attributes.add(attributeInfo.getName());
                        } catch (Throwable e) {
                        }
                    }
                }
                beanData.put("attributes", attributes);
                if(!attributes.isEmpty()) {
                    availableMetrics.add(beanData);
                }
            } catch (InstanceNotFoundException e) {
                LOGGER.warning(String.format("Exception=%s while getting bean=%s info what=%s", e.getClass().getName(), bean.toString(), e.getMessage()));
            } catch (IntrospectionException e) {
                LOGGER.warning(String.format("Exception=%s while getting bean=%s info what=%s", e.getClass().getName(), bean.toString(), e.getMessage()));
            } catch (ReflectionException e) {
                LOGGER.warning(String.format("Exception=%s while getting bean=%s info what=%s", e.getClass().getName(), bean.toString(), e.getMessage()));
            }
        }
        setInitialNamespaceIfNeeded();
        return availableMetrics;
    }

    private boolean shouldRetry() {
        return address != null && System.currentTimeMillis() - lastDisconnectionTimestamp > RECONNECTION_TIMEOUT_MS;
    }

    public List<BeanData> getMetrics(Tracer trcParent) {
        Tracer trcMetrics = trcParent.span("getMetrics");
        trcMetrics.enter(null);
        final List<BeanData> metrics = new ArrayList<BeanData>();
        if (connection != null || shouldRetry()) {
            try {
                setNetworkNamespaceIfNeeded();
                try {
                    if (connection == null) {
                        Tracer trc = trcMetrics.span("createConnection");
                        trc.enter(null);
                        connection = new Connection(address);
                        trc.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("isAlive", Boolean.toString(connection.isAlive())))));
                        lastBeanRefresh = 0;
                    }
                    if(System.currentTimeMillis() - lastBeanRefresh > BEAN_REFRESH_INTERVAL) {
                        Tracer trc = trcMetrics.span("beanRefresh");
                        trc.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("oldTimestamp", Long.toString(this.lastBeanRefresh)))));
                        refreshMatchingBeans();
                        lastBeanRefresh = System.currentTimeMillis();
                        trc.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("newTimestamp", Long.toString(this.lastBeanRefresh)))));
                    }

                    for (BeanInstance bean : matchingBeans) {
                        try {
                            BeanData beanMetrics = bean.retrieveMetrics(connection.getMbs());
                            if (!beanMetrics.getAttributes().isEmpty())
                            {
                                metrics.add(beanMetrics);
                            }
                        } catch (InstanceNotFoundException e) {
                            LOGGER.warning(String.format("Bean %s not found on process %d, forcing refresh", bean.getName().getCanonicalName(), pid));
                            lastBeanRefresh = 0;
                        } catch (ReflectionException e) {
                            LOGGER.warning(String.format("Cannot get attributes of Bean %s on process %d: %s", bean.getName().getCanonicalName(), pid, e.getMessage()));
                            lastBeanRefresh = 0;
                        }
                    }
                } catch (IOException ex) {
                    LOGGER.warning(String.format("Process %d agent is not responding reason=%s, declaring it down", pid, ex.getMessage().replaceAll("\n","")));
                    disconnect();
                } catch (SecurityException e) {
                    LOGGER.warning(String.format("Not enough permission to get attributes on process %d, disabling connection", pid));
                    disconnect();
                }
                setInitialNamespaceIfNeeded();
            } catch (final IOException ex) {
                LOGGER.warning(String.format("Cannot join namespace of pid=%d reason=%s, declaring it down", pid, ex.getMessage().replaceAll("\n","")));
                disconnect();
            }
        }
        trcMetrics.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("metricsSize", Integer.toString(metrics.size())))));
        return metrics;
    }

    private void setInitialNamespaceIfNeeded() {
        if (isOnAnotherContainer) {
            boolean namespaceSet = CLibrary.setInitialNamespace();
            if(!namespaceSet) {
                LOGGER.severe("Cannot set initial namespace");
            }
        }
    }

    private void setNetworkNamespaceIfNeeded() throws IOException {
        if (isOnAnotherContainer) {
            boolean namespaceChanged = CLibrary.setNamespace(pid);

            if(!namespaceChanged) {
                throw new IOException(String.format("Cannot set namespace"));
            }
        }
    }

    private void disconnect() {
        lastDisconnectionTimestamp = System.currentTimeMillis();
        if (connection != null) {
            connection.closeConnector();
            connection = null;
        }
    }

    /**
     * Cleanup resources used by MonitoredVM, to be used just before removing
     * this object. After this call, the object will be in an unusable state
     */
    public void cleanUp() {
        disconnect();
    }

    static private class BeanInstance {
        private ObjectName name;
        private Map<String, Config.BeanAttribute> attributesDesc;
        private String[] attributeNames;
        private Map<String, Double> counterSamples;

        private BeanInstance(ObjectName name, Config.BeanAttribute[] attributes) {
            this.name = name;
            this.attributeNames = new String[attributes.length];
            this.attributesDesc = new HashMap<String, Config.BeanAttribute>(attributes.length);
            this.counterSamples = new HashMap<String, Double>();

            for(int j = 0; j < attributes.length; ++j) {
                Config.BeanAttribute attributeDesc = attributes[j];
                attributeNames[j] = attributeDesc.getName();
                attributesDesc.put(attributeDesc.getName(), attributeDesc);
            }
        }

        private ObjectName getName() {
            return name;
        }

        private BeanData retrieveMetrics(MBeanServerConnection mbs) throws IOException, InstanceNotFoundException, ReflectionException {
            BeanData newSample = new BeanData(name);
            AttributeList attributeValues = mbs.getAttributes(name, attributeNames);
            for (Attribute attribute : attributeValues.asList()) {
                if (attribute == null)
                {
                    LOGGER.warning(String.format("null attribute on bean %s, probably configuration error", this.name));
                    continue;
                }
                final Config.BeanAttribute attributeDesc = attributesDesc.get(attribute.getName());
                if (attributeDesc.getType() == Config.BeanAttribute.Type.counter) {
                    // TODO: Counters are supported only for simple attributes right now
                    Double lastAbsoluteValue = counterSamples.get(attribute.getName());
                    Double newAbsoluteValue = BeanData.parseValueAsDouble(attribute.getValue());

                    if (lastAbsoluteValue != null) {
                        newSample.addAttribute(attributeDesc, newAbsoluteValue-lastAbsoluteValue);
                    }

                    counterSamples.put(attribute.getName(), newAbsoluteValue);
                } else {
                    newSample.addAttribute(attributeDesc, attribute.getValue());
                }
            }
            return newSample;
        }
    }
}

