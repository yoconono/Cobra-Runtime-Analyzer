package store

import (
	"testing"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

func TestUserCRUD(t *testing.T) {
	m := NewMemory()
	if n, _ := m.CountUsers(); n != 0 {
		t.Fatal("fresh store should have no users")
	}
	if err := m.CreateUser(model.User{Username: "admin", PassHash: "h1", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateUser(model.User{Username: "admin", PassHash: "h2"}); err != ErrExists {
		t.Errorf("duplicate create should ErrExists, got %v", err)
	}
	u, ok, _ := m.GetUser("admin")
	if !ok || u.PassHash != "h1" || !u.IsAdmin {
		t.Errorf("get user wrong: %+v ok=%v", u, ok)
	}
	if err := m.SetUserPassword("admin", "h3"); err != nil {
		t.Fatal(err)
	}
	if u, _, _ := m.GetUser("admin"); u.PassHash != "h3" {
		t.Error("password not updated")
	}
	if err := m.SetUserPassword("ghost", "x"); err != ErrNotFound {
		t.Errorf("update missing user should ErrNotFound, got %v", err)
	}
	_ = m.CreateUser(model.User{Username: "bob", PassHash: "hb"})
	n, _ := m.CountUsers()
	if n != 2 {
		t.Errorf("count=%d want 2", n)
	}
	if err := m.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	if n, _ := m.CountUsers(); n != 1 {
		t.Error("delete did not remove user")
	}
	users, _ := m.ListUsers()
	if len(users) != 1 || users[0].Username != "admin" {
		t.Errorf("list wrong: %+v", users)
	}
}
