package wizard

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// doc edits a YAML document in place, keeping comments, key order and
// ${VAR} references the wizard does not touch.
type doc struct {
	root yaml.Node
}

func parseDoc(raw []byte) (*doc, error) {
	d := &doc{}
	if err := yaml.Unmarshal(raw, &d.root); err != nil {
		return nil, err
	}
	if d.root.Kind == 0 {
		d.root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	return d, nil
}

func (d *doc) bytes() ([]byte, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&d.root); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func (d *doc) top() *yaml.Node { return d.root.Content[0] }

// value returns the node at path, or nil.
func (d *doc) value(path ...string) *yaml.Node {
	n := d.top()
	for _, key := range path {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		n = next
	}
	return n
}

func (d *doc) str(path ...string) string {
	if n := d.value(path...); n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}

func (d *doc) boolean(path ...string) bool {
	v, _ := strconv.ParseBool(d.str(path...))
	return v
}

func (d *doc) list(path ...string) []string {
	n := d.value(path...)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, c := range n.Content {
		if c.Kind == yaml.ScalarNode {
			out = append(out, c.Value)
		}
	}
	return out
}

// mapping returns the mapping at path, creating missing levels.
func (d *doc) mapping(path ...string) *yaml.Node {
	n := d.top()
	for _, key := range path {
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		if next == nil || next.Kind != yaml.MappingNode {
			if next == nil {
				next = &yaml.Node{Kind: yaml.MappingNode}
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, next)
			} else {
				*next = yaml.Node{Kind: yaml.MappingNode}
			}
		}
		n = next
	}
	return n
}

func (d *doc) setNode(v *yaml.Node, path ...string) {
	parent := d.mapping(path[:len(path)-1]...)
	key := path[len(path)-1]
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			// Keep comments attached to the old value.
			v.HeadComment, v.LineComment, v.FootComment = parent.Content[i+1].HeadComment, parent.Content[i+1].LineComment, parent.Content[i+1].FootComment
			parent.Content[i+1] = v
			return
		}
	}
	parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, v)
}

// setStr sets a string, leaving the node alone if the value is unchanged
// (so quoting style and comments survive).
func (d *doc) setStr(value string, path ...string) {
	if n := d.value(path...); n != nil && n.Kind == yaml.ScalarNode && n.Value == value {
		return
	}
	d.setNode(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}, path...)
}

func (d *doc) setInt(value int, path ...string) {
	d.setNode(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(value)}, path...)
}

func (d *doc) setBool(value bool, path ...string) {
	d.setNode(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(value)}, path...)
}

func (d *doc) setList(values []string, path ...string) {
	n := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, v := range values {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	d.setNode(n, path...)
}

// del removes the key at path, if present.
func (d *doc) del(path ...string) {
	parent := d.value(path[:len(path)-1]...)
	if len(path) == 1 {
		parent = d.top()
	}
	if parent == nil || parent.Kind != yaml.MappingNode {
		return
	}
	key := path[len(path)-1]
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
			return
		}
	}
}

// provider returns the auth.providers entry with this id, or nil.
func (d *doc) provider(id string) *yaml.Node {
	seq := d.value("auth", "providers")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(item.Content); i += 2 {
			if item.Content[i].Value == "id" && item.Content[i+1].Value == id {
				return item
			}
		}
	}
	return nil
}

func mapStr(m *yaml.Node, key string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1].Value
		}
	}
	return ""
}

func mapSet(m *yaml.Node, key, value string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			if m.Content[i+1].Value != value {
				m.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
			}
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

// setProvider creates or updates a provider entry.
func (d *doc) setProvider(id string, fields [][2]string) {
	item := d.provider(id)
	if item == nil {
		seq := d.value("auth", "providers")
		if seq == nil || seq.Kind != yaml.SequenceNode {
			seq = &yaml.Node{Kind: yaml.SequenceNode}
			d.setNode(seq, "auth", "providers")
		}
		item = &yaml.Node{Kind: yaml.MappingNode}
		mapSet(item, "id", id)
		seq.Content = append(seq.Content, item)
	}
	for _, f := range fields {
		mapSet(item, f[0], f[1])
	}
}

// delProvider removes a provider entry.
func (d *doc) delProvider(id string) {
	seq := d.value("auth", "providers")
	if seq == nil {
		return
	}
	for i, item := range seq.Content {
		if item.Kind == yaml.MappingNode && mapStr(item, "id") == id {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			break
		}
	}
	if len(seq.Content) == 0 {
		d.del("auth", "providers")
	}
}
