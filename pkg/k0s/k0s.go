package k0s

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/loft-sh/vcluster/pkg/config"
	"github.com/loft-sh/vcluster/pkg/util/commandwriter"
	"k8s.io/klog/v2"
)

const runDir = "/run/k0s"
const cidrPlaceholder = "CIDR_PLACEHOLDER"

var k0sConfig = `apiVersion: k0s.k0sproject.io/v1beta1
    kind: Cluster
    metadata:
      name: k0s
    spec:
      api:
        port: 6443
        k0sApiPort: 9443
        extraArgs:
          bind-address: 127.0.0.1
          enable-admission-plugins: NodeRestriction
          endpoint-reconciler-type: none
      network:
        {{- if .Values.serviceCIDR }}
        serviceCIDR: {{ .Values.serviceCIDR }}
        {{- else }}
        # Will be replaced automatically by the syncer container on first startup
        serviceCIDR: CIDR_PLACEHOLDER
        {{- end }}
        provider: custom
        {{- if .Values.networking.advanced.clusterDomain }}
        clusterDomain: {{ .Values.networking.advanced.clusterDomain }}
        {{- end}}
      controllerManager:
        extraArgs:
          {{- if not .Values.controlPlane.virtualScheduler.enabled }}
          controllers: '*,-nodeipam,-nodelifecycle,-persistentvolume-binder,-attachdetach,-persistentvolume-expander,-cloud-node-lifecycle,-ttl'
          {{- else }}
          controllers: '*,-nodeipam,-persistentvolume-binder,-attachdetach,-persistentvolume-expander,-cloud-node-lifecycle,-ttl'
          node-monitor-grace-period: 1h
          node-monitor-period: 1h
          {{- end }}
      {{- if .Values.controlPlane.backingStore.embeddedEtcd.enabled }}
      storage:
        etcd:
          externalCluster:
            endpoints: ["127.0.0.1:2379"]
            caFile: /data/k0s/pki/etcd/ca.crt
            etcdPrefix: "/registry"
            clientCertFile: /data/k0s/pki/apiserver-etcd-client.crt
            clientKeyFile: /data/k0s/pki/apiserver-etcd-client.key
      {{- end }}`

func StartK0S(ctx context.Context, cancel context.CancelFunc, vConfig *config.VirtualClusterConfig) error {
	// this is not really useful but go isn't happy if we don't cancel the context
	// everywhere
	defer cancel()

	// make sure we delete the contents of /run/k0s
	dirEntries, _ := os.ReadDir(runDir)
	for _, entry := range dirEntries {
		_ = os.RemoveAll(filepath.Join(runDir, entry.Name()))
	}

	// build args
	args := []string{}
	if len(vConfig.ControlPlane.Distro.K0S.Command) > 0 {
		args = append(args, vConfig.ControlPlane.Distro.K0S.Command...)
	} else {
		args = append(args, "/binaries/k0s")
		args = append(args, "controller")
		args = append(args, "--config=/tmp/k0s-config.yaml")
		args = append(args, "--data-dir=/data/k0s")
		args = append(args, "--status-socket=/run/k0s/status.sock")
		if vConfig.ControlPlane.VirtualScheduler.Enabled {
			args = append(args, "--disable-components=konnectivity-server,kube-scheduler,csr-approver,kube-proxy,coredns,network-provider,helm,metrics-server,worker-config")
		} else {
			args = append(args, "--disable-components=konnectivity-server,csr-approver,kube-proxy,coredns,network-provider,helm,metrics-server,worker-config")
		}
	}

	// add extra args
	args = append(args, vConfig.ControlPlane.Distro.K0S.ExtraArgs...)

	// check what writer we should use
	writer, err := commandwriter.NewCommandWriter("k0s")
	if err != nil {
		return err
	}
	defer writer.Close()

	// start the command
	klog.InfoS("Starting k0s", "args", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout = writer.Writer()
	cmd.Stderr = writer.Writer()
	cmd.Env = append(os.Environ(), "ETCD_UNSUPPORTED_ARCH=arm64")
	err = cmd.Run()

	// make sure we wait for scanner to be done
	writer.CloseAndWait(ctx, err)

	// regular stop case
	if err != nil && err.Error() != "signal: killed" {
		return err
	}
	return nil
}

func WriteK0sConfig(
	serviceCIDR string,
	vConfig *config.VirtualClusterConfig,
) error {

	// choose config
	configTemplate := k0sConfig
	if vConfig.Config.ControlPlane.Distro.K0S.Config != "" {
		configTemplate = vConfig.Config.ControlPlane.Distro.K0S.Config
	}

	// exec template
	outBytes, err := execTemplate(configTemplate, map[string]interface{}{
		"Values": vConfig.Config,
	})
	if err != nil {
		return fmt.Errorf("exec k0s config template: %w", err)
	}

	// apply changes
	updatedConfig := []byte(strings.ReplaceAll(string(outBytes), cidrPlaceholder, serviceCIDR))

	// write the config to file
	err = os.WriteFile("/tmp/k0s-config.yaml", updatedConfig, 0640)
	if err != nil {
		klog.Errorf("error while write k0s config to file: %s", err.Error())
		return err
	}

	return nil
}

func execTemplate(templateContents string, values map[string]interface{}) ([]byte, error) {
	t, err := template.New("").Parse(templateContents)
	if err != nil {
		return nil, err
	}

	b := &bytes.Buffer{}
	err = t.Execute(b, values)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
