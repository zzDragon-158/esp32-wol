function getSignalLevel(rssi) {
    if (rssi >= -50) return 4;
    else if (rssi >= -60) return 3;
    else if (rssi >= -70) return 2;
    else return 1;
}

async function fetchStatus() {
  const res = await fetch('/status');
  const status = await res.json();
  if (status["ipv4_addr"]) {
    document.getElementById("ipv4-addr").innerText = status["ipv4_addr"];
  }
  if (status["ipv6_addr"]) {
    document.getElementById("ipv6-addr").innerText = status["ipv6_addr"];
  }
}

async function fetchSSIDList() {
  // fetch ssids
  const res = await fetch('/scan');
  const ssids = await res.json();
  // const ssids = {
  //   "connected": {
  //       "Sunnada-OFFICE": {
  //           "rssi": -49,
  //           "lock": 2
  //       }
  //   },
  //   "saved": {},
  //   "nearby": {
  //       "Cassie": {
  //           "rssi": -71,
  //           "lock": 2
  //       },
  //       "Test_2.4G": {
  //           "rssi": -71,
  //           "lock": 2
  //       },
  //       "TP-LINK_B5A0ED": {
  //           "rssi": -72,
  //           "lock": 2
  //       },
  //       "ZWLAB-1": {
  //           "rssi": -72,
  //           "lock": 2
  //       },
  //       "ANKTION-GUEST": {
  //           "rssi": -73,
  //           "lock": 2
  //       },
  //       "imwifi": {
  //           "rssi": -73,
  //           "lock": 2
  //       },
  //       "work": {
  //           "rssi": -75,
  //           "lock": 2
  //       },
  //       "smartFz": {
  //           "rssi": -75,
  //           "lock": 2
  //       },
  //       "Bingo": {
  //           "rssi": -76,
  //           "lock": 2
  //       },
  //       "指挥车": {
  //           "rssi": -76,
  //           "lock": 2
  //       },
  //       "HiWiFi_000000": {
  //           "rssi": -77,
  //           "lock": 2
  //       },
  //       "huangguoqiang_2.4G": {
  //           "rssi": -77,
  //           "lock": 2
  //       },
  //       "lin073": {
  //           "rssi": -77,
  //           "lock": 2
  //       },
  //       "6666666": {
  //           "rssi": -79,
  //           "lock": 2
  //       },
  //       "JSZC-2.4G": {
  //           "rssi": -79,
  //           "lock": 2
  //       },
  //       "4F": {
  //           "rssi": -81,
  //           "lock": 2
  //       },
  //       "2F-OFFICE": {
  //           "rssi": -82,
  //           "lock": 2
  //       },
  //       "2L-shepin": {
  //           "rssi": -88,
  //           "lock": 1
  //       },
  //       "JSZC": {
  //           "rssi": -88,
  //           "lock": 2
  //       },
  //       "8888": {
  //           "rssi": -92,
  //           "lock": 2
  //       }
  //   }
  // };

  // connected
  if (ssids["connected"]) {
    const connectedListDiv = document.getElementById('connected-wlan');
    connectedListDiv.innerHTML = '';
    for (const [ssid, ap_info] of Object.entries(ssids["connected"])) {
      const signal_level = getSignalLevel(ap_info["rssi"]);
      const is_lock = ap_info["lock"];
      const item = document.createElement('div');
      item.className = 'connected-wlan-ssid';
      item.innerHTML = `
        <button class="ap" onclick="displayModal('connected-wlan-modal', '${ssid}')">
          <span class="signal signal-${signal_level}"></span>
          ${ssid}
          <span class="lock lock-${is_lock}"></span>
        </button>
      `;
      connectedListDiv.appendChild(item);
    }
  }

  // saved
  if (ssids["saved"]) {
    const savedListDiv = document.getElementById('saved-wlan');
    savedListDiv.innerHTML = '';
    for (const [ssid, ap_info] of Object.entries(ssids["saved"])) {
      const signal_level = getSignalLevel(ap_info["rssi"]);
      const is_lock = ap_info["lock"];
      const item = document.createElement('div');
      item.className = 'nearby-wlan-ssid';
      item.innerHTML = `
        <button class="ap" onclick="displayModal('saved-wlan-modal', '${ssid}')">
          <span class="signal signal-${signal_level}"></span>
          ${ssid}
          <span class="lock lock-${is_lock}"></span>
        </button>
      `;
      savedListDiv.appendChild(item);
    }
  }

  // nearby
  if (ssids["nearby"]) {
    const nearbyListDiv = document.getElementById('nearby-wlan');
    nearbyListDiv.innerHTML = '';
    for (const [ssid, ap_info] of Object.entries(ssids["nearby"])) {
      const signal_level = getSignalLevel(ap_info["rssi"]);
      const is_lock = ap_info["lock"];
      const item = document.createElement('div');
      item.className = 'nearby-wlan-ssid';
      item.innerHTML = `
        <button class="ap" onclick="displayModal('nearby-wlan-modal', '${ssid}')">
          <span class="signal signal-${signal_level}"></span>
          ${ssid}
          <span class="lock lock-${is_lock}"></span>
        </button>
      `;
      nearbyListDiv.appendChild(item);
    }
  }
}

function displayModal(id, ssid) {
  document.querySelector(`#${id} h3`).innerText = ssid;
  document.getElementById(id).style.display = 'flex';
}

function hideModal(id) {
  document.getElementById(id).style.display = 'none';
}

// disconnect from current wlan
async function handleConnectedWLANBtnEvent() {
  const group = 'connected';
  const ssid = document.getElementById('connected-wlan-ssid').textContent;
  document.getElementById("mask").style.display = 'flex';
  const res = await fetch('/wlan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ group, ssid })
  });
  const text = await res.text();
  alert(text);
  document.getElementById("mask").style.display = 'none';
  document.getElementById('connected-wlan-modal').style.display = 'none';
  fetchSSIDList();
}

// connect to saved wlan / forget wlan
async function handleSavedWLANBtnEvent(action) {
  const group = 'saved';
  const ssid = document.getElementById('saved-wlan-ssid').textContent;
  document.getElementById("mask").style.display = 'flex';
  const res = await fetch('/wlan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ group, action, ssid })
  });
  const text = await res.text();
  alert(text);
  document.getElementById("mask").style.display = 'none';
  document.getElementById('saved-wlan-modal').style.display = 'none';
  fetchSSIDList();
}

// connect to nearby wlan
document.getElementById("nearby-wlan-form").addEventListener("submit", async function (e) {
  const group = 'nearby';
  const ssid = document.getElementById('nearby-wlan-ssid').textContent;
  const passwd = document.getElementById('wlan-passwd').value;
  document.getElementById("mask").style.display = 'flex';
  const res = await fetch('/wlan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ group, ssid, passwd })
  });
  const text = await res.text();
  alert(text);
  document.getElementById("mask").style.display = 'none';
  document.getElementById('nearby-wlan-modal').style.display = 'none';
  fetchSSIDList();
});

document.getElementById("wol-form").addEventListener("submit", async function (e) {
  e.preventDefault();

  const mac_address = document.getElementById("mac-address").value.trim();
  const resultDiv = document.getElementById("send-result");

  if (!/^([0-9A-Fa-f]{2}[:\-]){5}([0-9A-Fa-f]{2})$/.test(mac_address)) {
    resultDiv.innerText = "Invalid MAC address format.";
    return;
  }

  const res = await fetch('/wol', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mac_address })
  });
  const text = await res.text();
  resultDiv.innerText = text;
});

function uploadFile() {
  const fileInput = document.getElementById('file-input');
  const file = fileInput.files[0];
  if (!file) {
    alert("请选择一个文件");
    return;
  }

  const uploadBtn = document.getElementById("upload-btn");
  const upgradeBtn = document.getElementById("upgrade-btn");
  const xhr = new XMLHttpRequest();
  uploadBtn.disabled = true;
  upgradeBtn.disabled = true;
  xhr.upload.onprogress = function (event) {
    if (event.lengthComputable) {
      const percent = Math.round((event.loaded / event.total) * 100);
      document.getElementById("upload-progress").style.display = "block";
      document.getElementById("upload-progress").value = percent;
      document.getElementById("progress-text").textContent = `上传进度：${percent}%`;
    }
  };
  xhr.onload = function () {
    uploadBtn.disabled = false;
    alert(xhr.responseText);
    if (xhr.status === 200) {
      upgradeBtn.disabled = false;
    }
    document.getElementById("upload-progress").style.display = "none";
  };
  xhr.onerror = function () {
    alert("上传出错");
    document.getElementById("upload-progress").style.display = "none";
  };
  xhr.onerror = function () {
    alert("上传出错");
    document.getElementById("upload-progress").style.display = "none";
  };

  xhr.open("POST", "/upload", true);
  xhr.setRequestHeader("Content-Type", "application/octet-stream");
  xhr.send(file);
}

async function performUpgrade() {
  document.getElementById("mask").style.display = 'flex';
  const res = await fetch('/upgrade', {
    method: 'GET',
  });
  const text = await res.text();
  alert(text);
  document.getElementById("mask").style.display = 'none';
}

window.onload = function () {
  fetchSSIDList();
  fetchStatus();
}