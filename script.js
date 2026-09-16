const openInfoBtn = document.getElementById("openInfoBtn");
const closeInfoBtn = document.getElementById("closeInfoBtn");
const mainPanel = document.getElementById("mainPanel");
const infoPanel = document.getElementById("infoPanel");

const chooseFileBtn = document.getElementById("chooseFileBtn");
const chooseFolderBtn = document.getElementById("chooseFolderBtn");
const filePicker = document.getElementById("filePicker");
const folderPicker = document.getElementById("folderPicker");
const selectedPath = document.getElementById("selectedPath");

const startScanBtn = document.getElementById("startScanBtn");
const progressText = document.getElementById("progressText");
const progressValue = document.getElementById("progressValue");
const progressCircle = document.getElementById("progressCircle");

const issuesList = document.getElementById("issuesList");
const issuesCount = document.getElementById("issuesCount");

var selectedItems = [];
var scanRunning = false;

var highRiskExtensions = [
  "exe", "msi", "bat", "cmd", "com", "scr", "pif",
  "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1",
  "jar", "apk", "dll", "sys", "hta", "reg"
];

var archiveExtensions = ["zip", "rar", "7z", "tar", "gz"];

var suspiciousWords = [
  "hack", "crack", "keygen", "patch", "virus",
  "malware", "trojan", "ransom", "stealer",
  "inject", "payload", "loader", "miner",
  "bypass", "exploit", "backdoor"
];

var doubleExtensions = [
  "jpg.exe", "jpeg.exe", "png.exe", "gif.exe",
  "pdf.exe", "doc.exe", "docx.exe", "txt.exe",
  "zip.exe", "rar.exe", "mp3.exe", "mp4.exe"
];

function getExtension(filename) {
  var lastDot = filename.lastIndexOf(".");
  if (lastDot === -1) return "";
  return filename.slice(lastDot + 1).toLowerCase();
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  var units = ["B", "KB", "MB", "GB"];
  var value = bytes;
  var unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value = value / 1024;
    unitIndex++;
  }

  return value.toFixed(value >= 10 ? 0 : 1) + " " + units[unitIndex];
}

function updateProgress(value) {
  var safeValue = Math.min(100, Math.max(0, value));
  progressText.textContent = safeValue + "%";
  progressValue.textContent = safeValue + "%";
  progressCircle.style.background =
    "conic-gradient(var(--primary) " + (safeValue * 3.6) + "deg, rgba(255,255,255,0.09) 0deg)";
}

function resetScanView() {
  updateProgress(0);
  issuesList.innerHTML = '<li class="issue empty">No suspicious files detected yet.</li>';
  issuesCount.textContent = "0 item";
}

function showMessage(message) {
  issuesList.innerHTML = '<li class="issue empty">' + message + "</li>";
  issuesCount.textContent = "0 item";
}

function renderIssues(items) {
  issuesList.innerHTML = "";

  if (items.length === 0) {
    issuesList.innerHTML =
      '<li class="issue empty">Scan completed. No suspicious patterns found.</li>';
    issuesCount.textContent = "0 item";
    return;
  }

  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    var li = document.createElement("li");
    li.className = "issue " + item.level;

    var title = document.createElement("strong");
    title.textContent = item.name;

    var description = document.createElement("span");
    description.textContent = item.reason;

    li.appendChild(title);
    li.appendChild(description);
    issuesList.appendChild(li);
  }

  issuesCount.textContent = items.length + " item" + (items.length > 1 ? "s" : "");
}

function inspectFile(file) {
  var name = file.name || "Unknown file";
  var lowerName = name.toLowerCase();
  var extension = getExtension(lowerName);
  var findings = [];

  for (var i = 0; i < doubleExtensions.length; i++) {
    if (lowerName.indexOf(doubleExtensions[i]) !== -1) {
      findings.push({
        name: name,
        level: "danger",
        reason: "High-risk double extension detected."
      });
      break;
    }
  }

  for (var j = 0; j < suspiciousWords.length; j++) {
    if (lowerName.indexOf(suspiciousWords[j]) !== -1) {
      findings.push({
        name: name,
        level: "danger",
        reason: 'Suspicious keyword in filename: "' + suspiciousWords[j] + '".'
      });
      break;
    }
  }

  if (highRiskExtensions.indexOf(extension) !== -1) {
    findings.push({
      name: name,
      level: "warning",
      reason: "Executable or script-like file type detected: ." + extension
    });
  }

  if (archiveExtensions.indexOf(extension) !== -1) {
    findings.push({
      name: name,
      level: "warning",
      reason: "Compressed archive detected. Contents require separate inspection."
    });
  }

  if (!extension && file.size > 0) {
    findings.push({
      name: name,
      level: "warning",
      reason: "File has no extension and should be reviewed manually."
    });
  }

  if (file.size > 100 * 1024 * 1024) {
    findings.push({
      name: name,
      level: "warning",
      reason: "Large file detected (" + formatBytes(file.size) + "). Review before opening."
    });
  }

  return findings;
}

function runInspection(files) {
  var allFindings = [];

  for (var i = 0; i < files.length; i++) {
    var findings = inspectFile(files[i]);
    allFindings = allFindings.concat(findings);
  }

  return allFindings.slice(0, 8);
}

function selectFiles(fileList, label) {
  if (!fileList || fileList.length === 0) return;

  selectedItems = Array.prototype.slice.call(fileList);

  if (selectedItems.length === 1) {
    selectedPath.value = selectedItems[0].name;
  } else {
    selectedPath.value = label + " selected (" + selectedItems.length + " files)";
  }

  resetScanView();
}

openInfoBtn.addEventListener("click", function () {
  mainPanel.classList.add("hidden");
  infoPanel.classList.remove("hidden");
});

closeInfoBtn.addEventListener("click", function () {
  infoPanel.classList.add("hidden");
  mainPanel.classList.remove("hidden");
});

chooseFileBtn.addEventListener("click", function () {
  filePicker.value = "";
  filePicker.click();
});

chooseFolderBtn.addEventListener("click", function () {
  folderPicker.value = "";
  folderPicker.click();
});

filePicker.addEventListener("change", function () {
  selectFiles(filePicker.files, "File");
});

folderPicker.addEventListener("change", function () {
  selectFiles(folderPicker.files, "Folder");
});

startScanBtn.addEventListener("click", function () {
  if (scanRunning) return;

  if (selectedItems.length === 0) {
    selectedPath.value = "Please choose a file or folder first";
    showMessage("Choose a file or folder before starting the scan.");
    return;
  }

  scanRunning = true;
  startScanBtn.textContent = "Scanning...";
  startScanBtn.classList.add("is-loading");
  startScanBtn.disabled = true;
  progressCircle.classList.add("is-scanning");

  issuesList.innerHTML =
    '<li class="issue loading">Loading</li><li class="issue loading">Loading</li>';
  issuesCount.textContent = "Scanning";

  var progress = 0;

  var timer = setInterval(function () {
    progress += Math.floor(Math.random() * 5) + 2;
    if (progress > 100) progress = 100;

    updateProgress(progress);

    if (progress >= 100) {
      clearInterval(timer);

      var findings = runInspection(selectedItems);
      renderIssues(findings);

      startScanBtn.textContent = "Start Scan";
      startScanBtn.classList.remove("is-loading");
      startScanBtn.disabled = false;
      progressCircle.classList.remove("is-scanning");
      scanRunning = false;
    }
  }, 80);
});

resetScanView();