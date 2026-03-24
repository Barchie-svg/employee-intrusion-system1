
  // Tab Switching Logic
  function switchTab(tabId, element) {
    // Hide all tabs
    document.querySelectorAll('.tab-section').forEach(el => el.classList.remove('active'));
    // Remove active class from all nav items
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    
    // Show selected tab
    document.getElementById('tab-' + tabId).classList.add('active');
    // Set active nav item
    element.classList.add('active');
    
    // Update Topbar Title
    const map = {
      'overview': 'Dashboard Overview',
      'companies': 'SaaS Companies & API Keys',
      'employees': 'Manage Employees',
      'logs': 'Intrusion Events',
      'audit': 'Administrator Audit Trails',
      'settings': 'System Settings'
    };
    document.getElementById('topbar-title').innerText = map[tabId];

    // On mobile, close sidebar after clicking
    if(window.innerWidth <= 768) {
      document.getElementById('sidebar').classList.remove('mobile-open');
    }
  }

  // Sidebar Toggle
  function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if(window.innerWidth <= 768) {
      sidebar.classList.toggle('mobile-open');
    } else {
      sidebar.classList.toggle('collapsed');
    }
  }

  // Modals
  function openResetModal(userId, username) {
    document.getElementById("resetTargetUser").innerText = username;
    document.getElementById("resetPwdForm").action = "/admin/reset_password/" + userId;
    document.getElementById("resetPwdModal").style.display = "flex";
  }
  function closeResetModal() { document.getElementById("resetPwdModal").style.display = "none"; }

  document.getElementById("addEmpModal").addEventListener("click", function (e) { if (e.target === this) closeAddModal(); });
  document.getElementById("addCompanyModal").addEventListener("click", function (e) { if (e.target === this) closeAddCompanyModal(); });
  document.getElementById("resetPwdModal").addEventListener("click", function (e) { if (e.target === this) closeResetModal(); });

  // ── Add Company Modal ──
  function openAddCompanyModal() {
    const modal = document.getElementById("addCompanyModal");
    modal.style.display = "flex";
    document.body.style.overflow = "hidden";
  }
  function closeAddCompanyModal() {
    const modal = document.getElementById("addCompanyModal");
    modal.style.display = "none";
    document.body.style.overflow = "";
    modal.querySelector("form").reset();
  }

  // ── Add Employee Modal ──
  function openAddModal() {
    const modal = document.getElementById("addEmpModal");
    modal.style.display = "flex";
    document.body.style.overflow = "hidden";
  }
  function closeAddModal() {
    const modal = document.getElementById("addEmpModal");
    modal.style.display = "none";
    document.body.style.overflow = "";
    // Clear the form fields on close
    modal.querySelector("form").reset();
  }

  function togglePwd(fieldId, icon) {
    const field = document.getElementById(fieldId);
    if (field.type === "password") { field.type = "text"; icon.innerHTML = '<i class="fa-solid fa-eye-slash"></i>'; } 
    else { field.type = "password"; icon.innerHTML = '<i class="fa-solid fa-eye"></i>'; }
  }

  // Chart Rendering
  if(true){
  const rawLogs = [];
  const rawTimes = [];
  const last10Times = rawTimes.slice(0, 10).map(t => t.substring(0, 16));
  const last10Reasons = rawLogs.slice(0, 10);

  const ctx = document.getElementById('intrusionChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: last10Times,
      datasets: [{
        label: 'Intrusion Events',
        data: last10Times.map(() => 1),
        backgroundColor: 'rgba(231, 76, 107, 0.5)',
        borderColor: 'rgba(231, 76, 107, 1)',
        borderWidth: 1,
        borderRadius: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: function(ctx2) { return 'Reason: ' + last10Reasons[ctx2.dataIndex]; } } }
      },
      scales: {
        x: { ticks: { color: '#9da4c2', font: { size: 10 } }, grid: { display: false } },
        y: { ticks: { color: '#9da4c2', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
      }
    }
  });
  }

  const ctxPie = document.getElementById('accountsChart').getContext('2d');
  new Chart(ctxPie, {
    type: 'doughnut',
    data: {
      labels: ['Active', 'Locked'],
      datasets: [{
        data: [[], []],
        backgroundColor: ['rgba(45, 212, 167, 0.8)', 'rgba(231, 76, 107, 0.8)'],
        borderColor: ['#2dd4a7', '#e74c6b'],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '75%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#e8eaf6' } }
      }
    }
  });


    function openEditHoursModal(companyId, companyName) {
      document.getElementById('editHoursTitle').textContent = `Working Hours: ${companyName}`;
      document.getElementById('editHoursForm').action = `/admin/companies/${companyId}/hours`;
      document.getElementById('editHoursModal').style.display = 'flex';
    }
    function closeEditHoursModal() {
      document.getElementById('editHoursModal').style.display = 'none';
    }

  // ─── Integration Guide Modal ───
  const IDS_HOST = window.location.origin;

  function openIntegrationGuide(companyName, apiKey) {
    document.getElementById('guideCompanyName').textContent = companyName;
    const snippet = `<script src="${IDS_HOST}/static/ids-shield.js"\n        data-api-key="${apiKey}"><\/script>`;
    document.getElementById('guideSnippet').textContent = snippet;
    const modal = document.getElementById('integrationGuideModal');
    modal.style.display = 'flex';
  }

  function closeIntegrationGuide() {
    document.getElementById('integrationGuideModal').style.display = 'none';
  }

  function copyGuideSnippet() {
    const text = document.getElementById('guideSnippet').textContent;
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById('guideSnippetCopyBtn');
      btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
      btn.style.background = 'rgba(45,218,155,0.2)';
      btn.style.color = 'var(--success)';
      setTimeout(() => {
        btn.innerHTML = '<i class="fa-solid fa-copy"></i> Copy';
        btn.style.background = 'rgba(108,92,231,0.2)';
        btn.style.color = '#a78bfa';
      }, 2000);
    });
  }

  // Close integration modal on backdrop click
  document.getElementById('integrationGuideModal').addEventListener('click', function(e) {
    if (e.target === this) closeIntegrationGuide();
  });

