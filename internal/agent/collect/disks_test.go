package collect

import (
	"errors"
	"testing"
)

func fakeStatfs(sizes map[string][2]uint64) StatfsFunc {
	return func(path string) (uint64, uint64, error) {
		s, ok := sizes[path]
		if !ok {
			return 0, 0, errors.New("stale file handle")
		}
		return s[0], s[1], nil
	}
}

func TestReadDisksSkipsPseudoAndCollapsesSameDevice(t *testing.T) {
	root := tree(t, map[string]string{"proc/mounts": "" +
		"proc /proc proc rw 0 0\n" +
		"tmpfs /run tmpfs rw 0 0\n" +
		"overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n" +
		"/dev/sda1 /var/lib/data ext4 rw 0 0\n" +
		"/dev/sda1 / ext4 rw 0 0\n" +
		"/dev/sdb1 /mnt/backup xfs rw 0 0\n"})
	disks, err := ReadDisks(root, fakeStatfs(map[string][2]uint64{"/": {1000, 400}, "/mnt/backup": {2000, 100}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(disks) != 2 {
		t.Fatalf("got %d disks, want 2: %+v", len(disks), disks)
	}
	if disks[0].Mount != "/" || disks[0].FS != "ext4" || disks[0].Total != 1000 || disks[0].Used != 400 {
		t.Errorf("same device must collapse to its shortest mount path: %+v", disks[0])
	}
	if disks[1].Mount != "/mnt/backup" {
		t.Errorf("second disk = %+v", disks[1])
	}
}

func TestReadDisksDecodesEscapedPathAndSurvivesStatfsFailure(t *testing.T) {
	root := tree(t, map[string]string{"proc/mounts": "" +
		"nas:/share /mnt/dead nfs4 rw 0 0\n" +
		`/dev/sdc1 /mnt/my\040disk ext4 rw 0 0` + "\n"})
	disks, err := ReadDisks(root, fakeStatfs(map[string][2]uint64{"/mnt/my disk": {500, 50}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(disks) != 1 || disks[0].Mount != "/mnt/my disk" {
		t.Errorf("want only the healthy disk with a decoded path, got %+v", disks)
	}
}

func TestReadDisksMissingMountsFile(t *testing.T) {
	if _, err := ReadDisks(t.TempDir(), fakeStatfs(nil)); err == nil {
		t.Error("missing /proc/mounts must be an error")
	}
}
