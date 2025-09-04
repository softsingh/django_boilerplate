
// Hide Sidebar by default on small screens
if (window.innerWidth <= 768) {
  document.body.classList.add('sidebar-hidden');
}

//////////////////// Dropdown ////////////////////

// Dropdown Notifications Menu
const notificationReads = document.querySelectorAll(
  '.dropdown-notifications-read'
);

notificationReads.forEach((notificationRead) => {
  notificationRead.addEventListener('click', (event) => {
    const notificationsItem = event.currentTarget.closest(
      '.dropdown-notifications-item'
    );
    notificationsItem.classList.toggle('mark-as-read');
    event.stopPropagation();
  });
});

const notificationArchives = document.querySelectorAll(
  '.dropdown-notifications-archive'
);

notificationArchives.forEach((notificationArchive) => {
  notificationArchive.addEventListener('click', (event) => {
    const notificationsItem = event.currentTarget.closest(
      '.dropdown-notifications-item'
    );
    notificationsItem.style.display = 'none';
    event.stopPropagation();
  });
});

//////////////////// Modal Confirm Demo ////////////////////

const tglDemoModalConfirm = document.querySelector(
  '[type="tgl-demo-modal-confirm"]'
);

tglDemoModalConfirm?.addEventListener('click', () => {
  modalConfirm('Are you sure to delete the file?', {
    iconType: bxIconEnum.DANGER,
    headingText: 'Delete',
    button1Text: 'Yes',
    button2Text: 'No',
    button3Text: 'Cancel',
  }).then((ret) => {
    const lblDemoModalConfirm = document.getElementById('lblDemoModalConfirm');
    if (lblDemoModalConfirm) {
      lblDemoModalConfirm.innerText = 'Returned = ' + ret;
    }
  });
})

//////////////////// Theme Toggle ////////////////////

// Apply saved preference on page load
if (localStorage.getItem('theme') === 'dark') {
  document.body.classList.add('dark-mode');
}

const themeToggle = document.querySelector('.theme-toggle .nav-link i');

if (themeToggle) {
  if (body.classList.contains('dark-mode')) {
    themeToggle.classList.remove('bx-moon');
    themeToggle.classList.add('bx-sun');
  } else {
    themeToggle.classList.remove('bx-sun');
    themeToggle.classList.add('bx-moon');
  }
}

themeToggle?.addEventListener('click', () => {
  body.classList.toggle('dark-mode');

  if (body.classList.contains('dark-mode')) {
    themeToggle.classList.remove('bx-moon');
    themeToggle.classList.add('bx-sun');
    localStorage.setItem('theme', 'dark');
  } else {
    themeToggle.classList.remove('bx-sun');
    themeToggle.classList.add('bx-moon');
    localStorage.setItem('theme', 'light');
  }
});

//////////////////// User List (Dashboard) ////////////////////

// Delete User List Item
const userListDelToggles = document.querySelectorAll(
  '[type="tgl-user-list-del"]'
);

userListDelToggles.forEach((delToggle) =>
  delToggle.addEventListener('click', (event) => {
    modalConfirm('Are you sure to delete the user?', {
      iconType: bxIconEnum.DANGER,
      headingText: 'Delete',
      button1Text: 'Yes',
      button2Text: 'No',
    }).then((ret) => {
      if (ret === 1) {
        const tableRow = delToggle.closest('tr');
        tableRow.parentNode.removeChild(tableRow);
      }
      else {
        return;
      }
    });
  })
);

//////////////////// Group List (Dashboard) ////////////////////

// Delete Group List Item
const groupListDelToggles = document.querySelectorAll(
  '[type="tgl-group-list-del"]'
);

groupListDelToggles.forEach((delToggle) =>
  delToggle.addEventListener('click', (event) => {
    modalConfirm('Are you sure to delete the group?', {
      iconType: bxIconEnum.DANGER,
      headingText: 'Delete',
      button1Text: 'Yes',
      button2Text: 'No',
    }).then((ret) => {
      if (ret === 1) {
        const tableRow = delToggle.closest('tr');
        tableRow.parentNode.removeChild(tableRow);
      }
      else {
        return;
      }
    });
  })
);
