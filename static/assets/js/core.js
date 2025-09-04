const body = document.querySelector('body');

const textColorEnum = {
  PRIMARY: 'text-primary',
  SECONDARY: 'text-secondary',
  SUCCESS: 'text-success',
  DANGER: 'text-danger',
  WARNING: 'text-warning',
  INFO: 'text-info'
}

const bxIconEnum = {
  NONE: '',
  SUCCESS: 'bx bx-check-circle text-success',
  DANGER: 'bx bx-x-circle text-danger',
  WARNING: 'bx bx-info-circle bx-rotate-180 text-warning',
  INFO: 'bx bx-info-circle text-info',
  QUESTION: 'bx bx-help-circle text-info'
}

//////////////////// Accordions ////////////////////

const accordionHeaders = document.querySelectorAll(
  '.accordion .accordion-header'
);

accordionHeaders.forEach((accordionHeader) =>
  accordionHeader.addEventListener('click', (event) => {
    const curentAccordionItem = accordionHeader.closest('.accordion-item');
    const parentName = curentAccordionItem.getAttribute('parent');

    if (parentName !== '') {
      const parent = document.getElementById(parentName);
      if (parent) {
        const accordionItems = parent.querySelectorAll('.accordion-item');
        accordionItems.forEach((accordionItem) => {
          if (accordionItem !== curentAccordionItem) {
            if (accordionItem.getAttribute('parent') === parentName) {
              accordionItem.classList.remove('open');
            }
          }
        });
      }
    }
    curentAccordionItem.classList.toggle('open');
    event.stopPropagation();
  })
);

//////////////////// Alerts ////////////////////

const alertDismissButtons = document.querySelectorAll(
  '.alert-dismissible .btn-close'
);

alertDismissButtons.forEach((alertDismissButton) =>
  alertDismissButton.addEventListener('click', (event) => {
    const alertDismiss = alertDismissButton.closest('.alert-dismissible');
    alertDismiss.classList.add('d-none');
    event.stopPropagation();
  })
);

//////////////////// Dropdown ////////////////////

const dropdownToggles = document.querySelectorAll('.dropdown-toggle');

dropdownToggles.forEach((dropdownToggle) =>
  dropdownToggle.addEventListener('click', (event) => {
    const dropdown = dropdownToggle.closest('.dropdown');
    const dropdownMenu = dropdown.querySelector('.dropdown-menu');
    hideAllDropdowns(event);
    dropdownMenu.classList.add('show');
    event.stopPropagation();
  })
);

function hideAllDropdowns(event) {
  const dropdownMenus = document.querySelectorAll('.dropdown-menu');

  dropdownMenus.forEach((dropdownMenu) => {
    if (dropdownMenu.classList.contains('show')) {
      const dropdown = dropdownMenu.closest('.dropdown');
      const dropdownToggle = dropdown.querySelector('.dropdown-toggle');
      if (event.currentTarget !== dropdownToggle) {
        dropdownMenu.classList.remove('show');
      }
    }
  });
}

//////////////////// Form Control ////////////////////

const invalidInputs = document.querySelectorAll('.form-control.invalid');

invalidInputs.forEach((invalidInput) => {
  invalidInput.addEventListener('input', (event) => {
    if (invalidInput.classList.contains('invalid')) {
      invalidInput.classList.remove('invalid');
    }
    event.stopPropagation();
  });
})


//////////////////// Modal (except ModalConfirm) ////////////////////

const modals = document.querySelectorAll('.modal:not(.modal-confirm)');
const modalDialogs = document.querySelectorAll(
  '.modal:not(.modal-confirm) .modal-dialog'
);
const modalContents = document.querySelectorAll(
  '.modal:not(.modal-confirm) .modal-content'
);
const modalToggles = document.querySelectorAll('[data-toggle="modal"]');
const modalDismissToggles = document.querySelectorAll(
  '.modal:not(.modal-confirm) [data-dismiss="modal"]'
);

// Show modal if modal toggle clicked
modalToggles.forEach((modalToggle) =>
  modalToggle.addEventListener('click', (event) => {
    hideAllDropdowns(event);
    const modalID = modalToggle.getAttribute('data-target');

    if (modalID) {
      const modal = document.getElementById(modalID);
      if (modal) {
        showModal(modal);
      }
    }
    event.stopPropagation();
  })
);

// Hide modal if modal dismiss toggle clicked
modalDismissToggles.forEach((modalDismissToggle) =>
  modalDismissToggle.addEventListener('click', (event) => {
    const modal = modalDismissToggle.closest('.modal');
    if (modal) {
      hideModal(modal);
    }
    event.stopPropagation();
  })
);

// Hide model when clicked outside model-content
modalDialogs.forEach((modalDialog) =>
  modalDialog.addEventListener('click', (event) => {
    if (event.target === modalDialog) {
      const modal = modalDialog.closest('.modal');
      hideModal(modal);
      event.stopPropagation();
    }
  })
);

// Hide model when clicked outside model-content
modals.forEach((modal) =>
  modal.addEventListener('click', (event) => {
    if (event.target === modal) {
      hideModal(modal);
      event.stopPropagation();
    }
  })
);

function showModal(modal) {
  const backdrop = document.createElement('div');
  backdrop.id = 'modalBackdrop';
  backdrop.className = 'modal-backdrop';
  backdrop.setAttribute('data-target', modal.id);
  document.body.appendChild(backdrop);
  modal.classList.add('show');
}

function hideModal(modal) {
  const backdrop = document.getElementById('modalBackdrop');
  if (backdrop) {
    backdrop.remove();
  }
  modal.classList.remove('show');
}

//////////////////// ModalConfirm ////////////////////

function modalConfirm(message, options = {}) {

  const {
    headingText = '',
    button1Text = '',
    button2Text = '',
    button3Text = '',
    iconType = bxIconEnum.NONE
  } = options;

  return new Promise((resolve) => {

    const modal = createModal();
    showModal(modal);

    const button1 = modal.querySelector("#button1")
    button1.onclick = () => {
      removeModal(modal);
      resolve(1);
    };

    const button2 = modal.querySelector("#button2")

    if (button2) {
      button2.onclick = () => {
        removeModal(modal);
        resolve(2);
      };
    }

    const button3 = modal.querySelector("#button3")
    if (button3) {
      button3.onclick = () => {
        removeModal(modal);
        resolve(3);
      };
    }

    function showModal(modal) {
      createBackdrop()
      modal.classList.add('show');
    }

    function removeModal(modal) {
      removeBackdrop()
      modal.remove();
      modal.classList.remove('show');
    }

    function createBackdrop() {
      const backdrop = document.createElement('div');
      backdrop.id = 'modalConfirmBackdrop';
      backdrop.className = 'modal-backdrop modal-confirm-backdrop';
      document.body.appendChild(backdrop);
    }

    function removeBackdrop() {
      const backdrop = document.getElementById('modalConfirmBackdrop');
      if (backdrop) {
        backdrop.remove();
      }
    }

    function createModal() {
      const modal = document.createElement('div');
      modal.id = 'modal-confirm';
      modal.className = 'modal modal-confirm';
      document.body.appendChild(modal);

      const modalDialog = document.createElement('div');
      modalDialog.className = 'modal-dialog modal-dialog-centered';
      modal.appendChild(modalDialog);

      const modalContent = document.createElement('div');
      modalContent.className = 'modal-content';
      modalDialog.appendChild(modalContent);

      const modalHeader = document.createElement('div');
      modalHeader.className = 'modal-header';
      modalContent.appendChild(modalHeader);

      headerChildDiv = document.createElement('div');
      headerChildDiv.className = 'd-flex align-items-center';
      modalHeader.appendChild(headerChildDiv);

      if (iconType) {
        modalIcon = document.createElement('i');
        modalIcon.className = iconType + ' fs-7 me-1';
        headerChildDiv.appendChild(modalIcon);
      }

      modalHeading = document.createElement('h6');
      modalHeading.innerText = headingText;
      headerChildDiv.appendChild(modalHeading);

      const modalBody = document.createElement('div');
      modalBody.className = 'modal-body';
      modalContent.appendChild(modalBody);

      const messagePara = document.createElement('p');
      messagePara.className = 'mb-2';
      messagePara.innerText = message;
      modalBody.appendChild(messagePara);

      const modalFooter = document.createElement('div');
      modalFooter.className = 'modal-footer';
      modalContent.appendChild(modalFooter);

      const footerDiv = document.createElement('div');
      footerDiv.className = 'd-flex align-items-center gap-2';
      modalFooter.appendChild(footerDiv);

      const button1 = document.createElement('button');
      button1.className = 'btn btn-primary';
      button1.id = 'button1';
      button1.innerText = button1Text ? button1Text : "OK";
      footerDiv.appendChild(button1);

      if (button2Text) {
        const button2 = document.createElement('button');

        if (button3Text)
          button2.className = 'btn btn-danger'
        else
          button2.className = 'btn btn-secondary';

        button2.id = 'button2';
        button2.innerText = button2Text;
        footerDiv.appendChild(button2);
      }

      if (button3Text && button2Text) {
        const button3 = document.createElement('button');
        button3.className = 'btn btn-secondary';
        button3.id = 'button3';
        button3.innerText = button3Text;
        footerDiv.appendChild(button3);
      }

      return modal;
    }
  });
}

//////////////////// Nav ////////////////////

const navItems = document.querySelectorAll('.nav>.nav-item');

navItems.forEach((navItem) =>
  navItem.addEventListener('click', (event) => {
    clearNavItemActive(navItem);
    navItem.classList.add('active');
    event.stopPropagation();
  })
);

function clearNavItemActive(currentNavItem) {
  navItems.forEach((navItem) => {
    if (navItem !== currentNavItem) {
      navItem.classList.remove('active');
    }
  });
}

//////////////////// Navbar ////////////////////

const navbarToggles = document.querySelectorAll('.navbar-toggle');

// Show modal if modal toggle clicked
navbarToggles.forEach((navbarToggle) =>
  navbarToggle.addEventListener('click', (event) => {
    hideAllDropdowns(event);

    const navbarCollapseID = navbarToggle.getAttribute('data-target');

    if (navbarCollapseID) {
      const navbarCollapse = document.getElementById(navbarCollapseID);
      if (navbarCollapse) {
        navbarCollapse.classList.toggle('show')
      }
    }
    event.stopPropagation();
  })
);

/////////////////// Pagination Overflow ////////////////////

const paginationOverflows = document.querySelectorAll('.pagination-overflow');
paginationOverflows?.forEach((paginationOverflow) => {
  const pageItems = paginationOverflow.querySelectorAll('.page-item');

  if (!pageItems)
    return;

  let pageItemCount = 0, activePageItem = 0, i = 0;

  for (i = 0; i < pageItems.length; i++) {
    if (
      !pageItems[i].classList.contains('page-item-first') &&
      !pageItems[i].classList.contains('page-item-previous') &&
      !pageItems[i].classList.contains('page-item-next') &&
      !pageItems[i].classList.contains('page-item-last')
    ) {
      pageItemCount++;
    }
  }

  // Apply overflow only if there are more than 4 page items
  if (pageItemCount <= 4) {
    return;
  }

  for (i = 0; i < pageItems.length; i++) {
    if (
      !pageItems[i].classList.contains('page-item-first') &&
      !pageItems[i].classList.contains('page-item-previous') &&
      !pageItems[i].classList.contains('page-item-next') &&
      !pageItems[i].classList.contains('page-item-last')
    ) {
      if (pageItems[i].classList.contains('active')) {
        activePageItem = i;
        break;
      }
    }
  }

  for (i = 0; i < pageItems.length; i++) {
    if (
      !pageItems[i]?.classList.contains('page-item-first') &&
      !pageItems[i]?.classList.contains('page-item-previous') &&
      !pageItems[i]?.classList.contains('page-item-next') &&
      !pageItems[i]?.classList.contains('page-item-last') &&
      i != activePageItem
    ) {
      if (i == activePageItem - 1 || i == activePageItem + 1) {
        let pageLink = pageItems[i]?.querySelector('.page-link');
        if (pageLink) {
          pageLink.setAttribute('href', '#');
          pageLink.innerHTML = '<i class="bx bx-dots-horizontal-rounded"></i>';
        }
      }
      else {
        pageItems[i]?.classList.add('d-none');
      }
    }
  }
});

/////////////////// Sidebar ////////////////////

// Sidebar Menu
const menuItems = document.querySelectorAll('.menu>.menu-item');

menuItems.forEach((menuItem) =>
  menuItem.addEventListener('click', (event) => {
    clearMenuItemOpenActive(menuItem);
    menuItem.classList.add('active');
    menuItem.classList.toggle('open');
    event.stopPropagation();
  })
);

// Sidebar Sub-Menu
const menuSubItems = document.querySelectorAll('.menu-sub>.menu-item');

menuSubItems.forEach((menuSubItem) =>
  menuSubItem.addEventListener('click', (event) => {
    clearMenuSubItemActive(menuSubItem);

    const menuSubSub = menuSubItem.querySelectorAll('.menu-sub');

    if (menuSubSub.length > 0) {
      menuSubItem.classList.toggle('open');
    } else {
      menuSubItem.classList.add('active');
    }

    event.stopPropagation();
  })
);

function clearMenuItemOpenActive(currentMenuItem) {
  menuItems.forEach((menuItem) => {
    if (menuItem !== currentMenuItem) {
      menuItem.classList.remove('active');
      menuItem.classList.remove('open');
    }
  });
}

function clearMenuSubItemActive(currentMenuSubItem) {
  menuSubItems.forEach((menuSubItem) => {
    if (menuSubItem !== currentMenuSubItem) {
      menuSubItem.classList.remove('active');
    }
  });
}

const sidebarToggles = document.querySelectorAll('[data-toggle="sidebar"]');

sidebarToggles.forEach((sidebarToggle) =>
  sidebarToggle.addEventListener('click', (event) => {
    body.classList.toggle('sidebar-hidden');
    event.stopPropagation();
  })
);

// Hide Sidebar when Sidebar Backdrop is clicked
const sidebarBackdrop = document.querySelector('.sidebar-backdrop');

sidebarBackdrop?.addEventListener('click', () => {
  document.body.classList.add('sidebar-hidden');
});

/////////////////// Toast ////////////////////

const toastToggles = document.querySelectorAll('[data-toggle="toast"]');

toastToggles.forEach((toastToggle) =>
  toastToggle.addEventListener('click', (event) => {
    const targetToast = toastToggle.getAttribute('data-target');
    const toast = document.querySelector(targetToast)

    if (toast) {

      let delay = parseInt(toast.getAttribute('data-delay'), 10);

      if (isNaN(delay)) {
        delay = 3000;
      }

      toast.style.display = 'block';
      toast.classList.add('show');

      setTimeout(() => {
        toast.classList.remove('show');
        toast.classList.add('hide');

        // Wait for animation to finish before hiding completely
        setTimeout(() => {
          toast.classList.remove('hide');
          toast.style.display = 'none';
        }, 300); // Match animation duration

      }, delay);
    }

    event.stopPropagation();
  })
);


const toastCloseButtons = document.querySelectorAll('.toast-header .btn-close');

toastCloseButtons.forEach((toastCloseButton) =>
  toastCloseButton.addEventListener('click', (event) => {
    const toast = toastCloseButton.closest('.toast');

    if (toast) {
      toast.classList.remove('show');
      toast.classList.remove('hide');
      toast.style.display = 'none';
    }

    event.stopPropagation();
  })
);

/////////////////// Tooltip ////////////////////

const tooltipToggles = document.querySelectorAll('[data-toggle="tooltip"]');

tooltipToggles.forEach((tooltipToggle) => {

  tooltipToggle.addEventListener('mouseenter', (event) => {
    const tooltipID = "tooltip_" + getRandomInt(1, 65535);
    const tooltip = new Tooltip(tooltipToggle, tooltipID);
    if (!tooltip) return;

    tooltip.classList.add('show');
    tooltipToggle.setAttribute('data-target', "#" + tooltipID);

    let rect = tooltipToggle.getBoundingClientRect();
    let tooltipPlacement = tooltipToggle.getAttribute('data-placement');

    switch (tooltipPlacement) {
      case 'top':
        tooltip.style.left = rect.left + window.pageXOffset + (tooltipToggle.offsetWidth - tooltip.offsetWidth) / 2 + 'px';
        tooltip.style.top = rect.top + window.pageYOffset - tooltip.offsetHeight - 2 + 'px';
        break;

      case 'bottom':
        tooltip.style.left = rect.left + window.pageXOffset + (tooltipToggle.offsetWidth - tooltip.offsetWidth) / 2 + 'px';
        tooltip.style.top = rect.top + window.pageYOffset + tooltipToggle.offsetHeight + 2 + 'px';
        break;

      case 'left':
        tooltip.style.left = rect.left + window.pageXOffset - tooltip.offsetWidth - 2 + 'px';
        tooltip.style.top = rect.top + window.pageYOffset + (tooltipToggle.offsetHeight - tooltip.offsetHeight) / 2 + 'px';
        break;

      case 'right':
        tooltip.style.left = rect.left + window.pageXOffset + tooltipToggle.offsetWidth + 2 + 'px';
        tooltip.style.top = rect.top + window.pageYOffset + (tooltipToggle.offsetHeight - tooltip.offsetHeight) / 2 + 'px';
        break;
    }
  });

  tooltipToggle.addEventListener('mouseleave', (event) => {
    const tooltipTarget = tooltipToggle.getAttribute('data-target');
    const tooltip = document.querySelector(tooltipTarget);
    if (tooltip) {
      tooltip.remove();
    }
    tooltipToggle.removeAttribute('data-target');
  });

});

function Tooltip(el, tooltipID) {
  let tooltipText = el.getAttribute('data-title');
  if (!tooltipText) return;

  let tooltipPlacement = el.getAttribute('data-placement');

  switch (tooltipPlacement) {
    case 'top':
      tooltipPlacement = 'tooltip-top';
      break;

    case 'bottom':
      tooltipPlacement = 'tooltip-bottom';
      break;

    case 'left':
      tooltipPlacement = 'tooltip-left';
      break;

    case 'right':
      tooltipPlacement = 'tooltip-right';
      break;

    default:
      tooltipPlacement = 'tooltip-top';
  }

  let tooltipDiv = document.createElement('div');
  tooltipDiv.className = `tooltip ${tooltipPlacement}`;

  const tooltipCustomClass = el.getAttribute('data-custom-class');

  if (tooltipCustomClass) {
    tooltipDiv.classList.add(tooltipCustomClass);
  }

  tooltipDiv.setAttribute('id', tooltipID);

  let tooltipInner = document.createElement('div');
  tooltipInner.className = 'tooltip-inner';
  tooltipInner.textContent = tooltipText;

  let tooltipArrow = document.createElement('div');
  tooltipArrow.className = 'tooltip-arrow';

  tooltipDiv.appendChild(tooltipInner);
  tooltipDiv.appendChild(tooltipArrow);

  document.body.appendChild(tooltipDiv);

  return tooltipDiv;
}

//////////////////// Click on Empty Area ////////////////////

document.addEventListener('click', (event) => {
  hideAllDropdowns(event);
});

/////////////////// Library Functions ////////////////////

function getRandomInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}