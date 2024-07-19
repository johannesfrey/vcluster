package testing

import (
	"context"
	"fmt"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/loft-sh/vcluster/pkg/config"
	synccontext "github.com/loft-sh/vcluster/pkg/controllers/syncer/context"
	"github.com/loft-sh/vcluster/pkg/scheme"
	testingutil "github.com/loft-sh/vcluster/pkg/util/testing"
	"gotest.tools/assert"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	FakeClientResourceVersion = "999"
)

type Compare func(obj1 runtime.Object, obj2 runtime.Object) bool

type NewContextFunc func(vConfig *config.VirtualClusterConfig, pClient *testingutil.FakeIndexClient, vClient *testingutil.FakeIndexClient) *synccontext.RegisterContext

type SyncTest struct {
	ExpectedPhysicalState map[schema.GroupVersionKind][]runtime.Object
	ExpectedVirtualState  map[schema.GroupVersionKind][]runtime.Object
	Sync                  func(ctx *synccontext.RegisterContext)
	Compare               Compare
	Name                  string
	InitialPhysicalState  []runtime.Object
	InitialVirtualState   []runtime.Object
	AdjustConfig          func(vConfig *config.VirtualClusterConfig)
}

func RunTests(t *testing.T, tests []*SyncTest) {
	// run focus first
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			test.Run(t, test, NewFakeRegisterContext)
		})
	}
}

func RunTestsWithContext(t *testing.T, createContext NewContextFunc, tests []*SyncTest) {
	for _, test := range tests {
		test.Run(t, test, createContext)
	}
}

func (s *SyncTest) Run(t *testing.T, test *SyncTest, createContext NewContextFunc) {
	ctx := context.Background()

	physicalState := []runtime.Object{}
	for _, o := range s.InitialPhysicalState {
		physicalState = append(physicalState, o.DeepCopyObject())
	}
	virtualState := []runtime.Object{}
	for _, o := range s.InitialVirtualState {
		virtualState = append(virtualState, o.DeepCopyObject())
	}

	pClient := testingutil.NewFakeClient(scheme.Scheme, physicalState...)
	vClient := testingutil.NewFakeClient(scheme.Scheme, virtualState...)
	vConfig := NewFakeConfig()
	if test.AdjustConfig != nil {
		test.AdjustConfig(vConfig)
	}

	// do the sync
	s.Sync(createContext(vConfig, pClient, vClient))

	// Compare states
	for gvk, objs := range s.ExpectedPhysicalState {
		err := CompareObjs(ctx, t, s.Name+" physical state", pClient, gvk, scheme.Scheme, objs, s.Compare)
		if err != nil {
			t.Fatalf("%s - Physical State mismatch: %v", s.Name, err)
		}
	}
	for gvk, objs := range s.ExpectedVirtualState {
		err := CompareObjs(ctx, t, s.Name+" virtual state", vClient, gvk, scheme.Scheme, objs, s.Compare)
		if err != nil {
			t.Fatalf("%s - Virtual State mismatch: %v", s.Name, err)
		}
	}
}

func CompareObjs(ctx context.Context, t *testing.T, state string, c client.Client, gvk schema.GroupVersionKind, scheme *runtime.Scheme, objs []runtime.Object, compare Compare) error {
	listGvk := gvk.GroupVersion().WithKind(gvk.Kind + "List")
	list, err := scheme.New(listGvk)
	if err != nil {
		if !runtime.IsNotRegisteredError(err) {
			return err
		}

		list = &unstructured.UnstructuredList{}
	}

	uList, ok := list.(*unstructured.UnstructuredList)
	if ok {
		uList.SetKind(listGvk.Kind)
		uList.SetAPIVersion(listGvk.GroupVersion().String())
	}

	err = c.List(ctx, list.(client.ObjectList))
	if err != nil {
		return fmt.Errorf("list objects: %w", err)
	}

	existingObjs, err := meta.ExtractList(list)
	if err != nil {
		return fmt.Errorf("extract list: %w", err)
	}

	if len(objs) != len(existingObjs) {
		expectedObjsYaml, err := yaml.Marshal(objs)
		if err != nil {
			return err
		}
		existingObjsYaml, err := yaml.Marshal(existingObjs)
		if err != nil {
			return err
		}

		t.Logf("\n\nExpected: \n%s\n\nExisting: \n%s\n", expectedObjsYaml, existingObjsYaml)
		assert.Equal(t, string(expectedObjsYaml), string(existingObjsYaml), state+" mismatch")
		return fmt.Errorf("expected objs and existing objs length do not match (%d != %d)", len(objs), len(existingObjs))
	}

	for _, expectedObj := range objs {
		expectedObj = stripObject(expectedObj)
		expectedAccessor, err := meta.Accessor(expectedObj)
		if err != nil {
			return err
		}

		found := false
		for _, existingObjRaw := range existingObjs {
			clientObj, ok := existingObjRaw.(*unstructured.Unstructured)
			if ok {
				clientObj.SetKind(gvk.Kind)
				clientObj.SetAPIVersion(gvk.GroupVersion().String())
			}

			existingAccessor, err := meta.Accessor(existingObjRaw)
			if err != nil {
				return err
			}

			if expectedAccessor.GetName() == existingAccessor.GetName() && expectedAccessor.GetNamespace() == existingAccessor.GetNamespace() {
				found = true

				// compare objs
				existingObj := stripObject(existingObjRaw)
				expectedObjsYaml, err := yaml.Marshal(expectedObj)
				if err != nil {
					return err
				}
				existingObjsYaml, err := yaml.Marshal(existingObj)
				if err != nil {
					return err
				}

				isEqual := false
				if compare != nil {
					isEqual = compare(expectedObj, existingObj)
				} else {
					isEqual = apiequality.Semantic.DeepEqual(expectedObj, existingObj) || string(expectedObjsYaml) == string(existingObjsYaml)
				}

				if !isEqual {
					t.Logf("\n\nExpected: \n%s\n\nExisting: \n%s\n", expectedObjsYaml, existingObjsYaml)
					assert.Equal(t, string(expectedObjsYaml), string(existingObjsYaml), state+" mismatch")
					return fmt.Errorf("expected obj %s/%s and existing obj are different", expectedAccessor.GetNamespace(), expectedAccessor.GetName())
				}

				break
			}
		}

		if !found {
			return fmt.Errorf("expected obj %s/%s was not found", expectedAccessor.GetNamespace(), expectedAccessor.GetName())
		}
	}

	return nil
}

func stripObject(obj runtime.Object) runtime.Object {
	newObj := obj.DeepCopyObject()
	accessor, err := meta.Accessor(newObj)
	if err != nil {
		panic(err)
	}

	accessor.SetResourceVersion("")
	accessor.SetOwnerReferences(nil)
	accessor.SetGeneration(0)
	accessor.SetUID("")
	accessor.SetSelfLink("")
	accessor.SetManagedFields(nil)

	a := accessor.GetAnnotations()
	if a != nil {
		delete(a, "vcluster.loft.sh/apply")
	}
	if len(a) == 0 {
		accessor.SetAnnotations(nil)
	}

	l := accessor.GetLabels()
	if l != nil {
		delete(l, "vcluster.loft.sh/managed-by")
	}
	if len(l) == 0 {
		accessor.SetLabels(nil)
	}

	_, ok := newObj.(*unstructured.Unstructured)
	if !ok {
		typeAccessor, err := meta.TypeAccessor(newObj)
		if err != nil {
			panic(err)
		}

		typeAccessor.SetAPIVersion("")
		typeAccessor.SetKind("")
	}

	return newObj
}
