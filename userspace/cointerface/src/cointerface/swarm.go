package main

import (
	draiosproto "protorepo/agent-be/proto"
	"github.com/draios/protorepo/sdc_internal"
	"context"
	"errors"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/gogo/protobuf/proto"
	"strings"
)

func labelsToProtobuf(labels map[string]string) (ret []*draiosproto.SwarmPair) {
	for k, v := range labels {
		// Strip com.docker. from labels
		ret = append(ret, &draiosproto.SwarmPair{Key: proto.String(strings.TrimPrefix(k, "com.docker.")), Value: proto.String(v)})
	}
	return
}

func virtualIPsToProtobuf(vIPs []swarm.EndpointVirtualIP) (ret []string) {
	for _, vip := range vIPs {
		ret = append(ret, vip.Addr)
	}
	return
}

func portsToProtobuf(ports []swarm.PortConfig) (ret []*draiosproto.SwarmPort) {
	for _, port := range ports {
		ret = append(ret, &draiosproto.SwarmPort{Port: proto.Uint32(port.TargetPort),
			PublishedPort: proto.Uint32(port.PublishedPort),
			Protocol:      proto.String(string(port.Protocol))})
	}
	return
}

func serviceToProtobuf(service swarm.Service, taskmap map[string]uint64) *draiosproto.SwarmService {
	srv := draiosproto.SwarmService{Common: &draiosproto.SwarmCommon{
		Id:     proto.String(service.ID),
		Name:   proto.String(service.Spec.Name),
		Labels: labelsToProtobuf(service.Spec.Labels)},
		VirtualIps: virtualIPsToProtobuf(service.Endpoint.VirtualIPs),
		Ports:      portsToProtobuf(service.Endpoint.Ports),
	}
	if service.Spec.Mode.Replicated != nil {
		mode := draiosproto.SwarmServiceMode_REPLICATED
		srv.Mode = &mode
		srv.SpecReplicas = service.Spec.Mode.Replicated.Replicas
	} else if service.Spec.Mode.Global != nil {
		mode := draiosproto.SwarmServiceMode_GLOBAL
		srv.Mode = &mode
	}
	num, exist := taskmap[service.ID]
	if !exist {
		num = 0
	}
	srv.Tasks = &num
	return &srv
}

func taskToProtobuf(task swarm.Task, srvmap map[string]string) *draiosproto.SwarmTask {
	cidlen := len(task.Status.ContainerStatus.ContainerID)
	if cidlen > 12 {
		cidlen = 12
	}

	name := task.Name
	if len(name) < 1 {
		serviceName, exist := srvmap[task.ServiceID]
		if !exist {
			serviceName = ""
		}

		// This is the way `docker service ps` constructs the task name
		if task.Slot != 0 {
			name = fmt.Sprintf("%v.%v", serviceName, task.Slot)
		} else {
			name = fmt.Sprintf("%v.%v", serviceName, task.NodeID)
		}
	}

	return &draiosproto.SwarmTask{Common: &draiosproto.SwarmCommon{
		Id:   proto.String(task.ID),
		Name: proto.String(name),
	},
		ServiceId:   proto.String(task.ServiceID),
		NodeId:      proto.String(task.NodeID),
		ContainerId: proto.String(task.Status.ContainerStatus.ContainerID[:cidlen]),
		State:       proto.String(string(task.Status.State))}
}

func nodeToProtobuf(node swarm.Node) *draiosproto.SwarmNode {
	var addr string
	// It looks that sometimes node.Status.Addr is 127.0.0.1
	// on managers, so for them report the ManagerStatus.Addr
	// docker issue: https://github.com/docker/docker/issues/30119
	if node.ManagerStatus != nil {
		addr = strings.Split(node.ManagerStatus.Addr, ":")[0]
	} else {
		addr = node.Status.Addr
	}
	sn := draiosproto.SwarmNode{
		Common: &draiosproto.SwarmCommon{
			Id:     proto.String(node.ID),
			Name:   proto.String(node.Description.Hostname),
			Labels: labelsToProtobuf(node.Spec.Labels),
		},
		Role:         proto.String(string(node.Spec.Role)),
		IpAddress:    proto.String(addr),
		Version:      proto.String(node.Description.Engine.EngineVersion),
		Availability: proto.String(string(node.Spec.Availability)),
		State:        proto.String(string(node.Status.State))}
	if node.ManagerStatus != nil {
		sn.Manager = &draiosproto.SwarmManager{
			Leader:       proto.Bool(node.ManagerStatus.Leader),
			Reachability: proto.String(string(node.ManagerStatus.Reachability))}
	}
	return &sn
}

func quorum(nodes []swarm.Node) *bool {
	var on, total uint32 = 0, 0
	for _, node := range nodes {
		if node.ManagerStatus != nil {
			if node.ManagerStatus.Reachability == swarm.ReachabilityReachable {
				on++
			}
			total++
		}
	}
	var q bool = on >= (total/2)+1
	return &q
}

func getSwarmState(ctx context.Context, cmd *sdc_internal.SwarmStateCommand) (*sdc_internal.SwarmStateResult, error) {
	cli, err := GetDockerClient("v1.24")
	if err != nil {
		return nil, err
	}

	info, err := cli.Info(ctx)
	if err != nil {
		ferr := fmt.Errorf("Could not get docker client info: %s", err)
		return nil, ferr
	}

	isManager := info.Swarm.ControlAvailable

	nodeId := proto.String(info.Swarm.NodeID)
	m := &draiosproto.SwarmState{NodeId: nodeId}

	// If this host is not a manager we won't be able to get any swarm state
	// from it, so treat it as an error and the agent will reduce the
	// poll-frequency
	if !isManager {
		ferr := errors.New("Host is not a swarm manager")
		log.Debug(ferr)
		res := &sdc_internal.SwarmStateResult{}
		res.Successful = proto.Bool(false)
		res.Errstr = proto.String(ferr.Error())
		res.State = m
		return res, nil
	}

	taskmap := make(map[string]uint64)    // count of running tasks per service id
	servicemap := make(map[string]string) // service id to name

	args := filters.NewArgs()
	args.Add("desired-state", "running")
	args.Add("desired-state", "accepted")

	services, err := cli.ServiceList(ctx, types.ServiceListOptions{})
	if err == nil {
		for _, service := range services {
			servicemap[service.ID] = service.Spec.Name
		}
	} else {
		log.Errorf("Error fetching services: %s\n", err)
	}

	tasks, err := cli.TaskList(ctx, types.TaskListOptions{Filters: args})
	if err == nil {
		for _, task := range tasks {
			if task.Status.ContainerStatus == nil {
				log.Infof("Skipping Swarm task with no ContainerStatus: id=%s service_id=%s node_id=%s status.state=%s\n", task.ID, task.ServiceID, task.NodeID, task.Status.State)
				continue
			}
			m.Tasks = append(m.Tasks, taskToProtobuf(task, servicemap))
			// fmt.Printf("task id=%s name=%s service=%s node=%s status=%s containerid=%s\n", task.ID, task.Name, task.ServiceID, task.NodeID, task.Status.State, task.Status.ContainerStatus.ContainerID[:12])
			if task.Status.State == swarm.TaskStateRunning && len(task.ServiceID) > 0 {
				taskmap[task.ServiceID]++
			}
		}
	} else {
		log.Errorf("Error fetching tasks: %s\n", err)
	}

	for _, service := range services {
		m.Services = append(m.Services, serviceToProtobuf(service, taskmap))
	}

	if nodes, err := cli.NodeList(ctx, types.NodeListOptions{}); err == nil {
		for _, node := range nodes {
			m.Nodes = append(m.Nodes, nodeToProtobuf(node))
			// fmt.Printf("node id=%s name=%s role=%s availability=%s\n", node.ID, node.Description.Hostname, node.Spec.Role, node.Spec.Availability)
		}
		m.Quorum = quorum(nodes)
	} else {
		log.Errorf("Error fetching nodes: %s\n", err)
	}

	res := &sdc_internal.SwarmStateResult{}
	res.Successful = proto.Bool(err == nil)
	if err != nil {
		res.Errstr = proto.String(err.Error())
	}
	res.State = m

	return res, nil
}
