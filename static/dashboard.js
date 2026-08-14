// Paket/alarm icerigi dogrudan ag trafiginden (DNS sorgusu, HTTP path/header,
// TLS SNI vb.) geldigi icin tamamen saldirgan kontrolunde olabilir. innerHTML
// ile basilmadan once HER ZAMAN bu fonksiyondan gecirilmeli.
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function initDashboard() {
  // 1. Data Bootstrap
  const dataElement = document.getElementById('analysis-data');
  if (!dataElement) return;
  
  let data = {};
  try {
    data = JSON.parse(dataElement.textContent);
  } catch (err) {
    console.error("Analiz verisi ayrıştırılamadı:", err);
    return;
  }

  let visData = null;
  let network = null;

  // Siber Güvenlik Terimleri Sözlüğü (Sade Dilli)
  const threatGlossary = {
    "ARP Spoofing / Poisoning Tespiti": {
      explanation: "Ağınızdaki bir cihaz, kendisini internet ağ geçidi (modem) gibi tanıtmaya çalışıyor. Bu durum, tüm internet trafiğinizi araya girip gizlice okuma (Man-in-the-Middle) saldırısının en net göstergesidir.",
      remediation: "Yerel ağınızda şüpheli/tanınmayan bir cihaz var. Modeminizi yeniden başlatın, WPA3 şifreleme kullanın ve ağ şifrenizi hemen değiştirin. Halka açık ortak Wi-Fi ağlarındaysanız derhal bağlantıyı kesin."
    },
    "SQL Injection (SQLi) Denemesi": {
      explanation: "Web sitenizin veri tabanını ele geçirmeye çalışan bir saldırgan, adres çubuğuna veri tabanı sorgu komutları (UNION SELECT, OR 1=1 vb.) ekleyerek sızma girişimi yapmış.",
      remediation: "Eğer bu web sitesi size aitse, girdi doğrulama (input validation) ve SQL parametrelendirme (prepared statements) yöntemlerini kullanın. Web Uygulaması Güvenlik Duvarı (WAF) aktif edin."
    },
    "Cross-Site Scripting (XSS) Denemesi": {
      explanation: "Sitenizi ziyaret eden diğer kullanıcıların tarayıcılarında çalıştırılmak üzere, istek adresine zararlı JavaScript kodları enjekte edilmeye çalışılmış. Çerez çalma veya kimlik hırsızlığı riski taşır.",
      remediation: "Kullanıcı girdilerini ekrana basmadan önce HTML filtrelemesinden geçirin (output encoding). CSP (Content Security Policy) kurallarını aktif hale getirin."
    },
    "Dizin Geçişi (Path Traversal) Denemesi": {
      explanation: "Saldırgan, sistemdeki gizli dosyalara (örneğin Linux sistemlerde /etc/passwd şifre dosyası gibi) erişmek için dizin atlama ('../../') karakterlerini kullanarak sunucu klasörlerinde gezinmeye çalışmış.",
      remediation: "Dosya erişim yetkilerini sınırlayın, kullanıcı girdilerinden dosya yolu parametrelerini dinamik olarak almaktan kaçının ve dosya okuma yollarını sabitleyin (chroot/sandbox)."
    },
    "Şüpheli Güvenlik Tarayıcısı Tespiti": {
      explanation: "Nmap, Sqlmap veya Nikto gibi otomatik güvenlik/zayıflık tarama araçları, ağınızı veya sitenizi tarayarak açık kapıları ve zayıflıkları bulmaya çalışmış.",
      remediation: "Bu durum sızma öncesi bilgi toplama (reconnaissance) faaliyetidir. Tarama yapan IP adresini sunucu güvenlik duvarından (Firewall) kalıcı olarak engelleyin."
    },
    "Açık Metin Kimlik Doğrulama İletimi": {
      explanation: "HTTP (şifresiz) üzerinden kimlik bilgileri gönderiliyor. Trafiği dinleyen bir saldırgan şifrenizi olduğu gibi görebilir.",
      remediation: "Tüm web trafiğinde HTTPS (SSL/TLS) kullanımını zorunlu hale getirin. Şifresiz HTTP protokolüyle kimlik doğrulaması yapmayın."
    },
    "Açık Metin Hassas Veri Sızıntısı": {
      explanation: "Ağ trafiğinde şifrelenmemiş (açık metin) olarak şifre, parola, API anahtarı veya gizli bir parametre geçiyor. Aynı ağdaki herkes bu şifreyi görebilir.",
      remediation: "İletişim için mutlaka şifreli protokoller (HTTPS, FTPS, SFTP) kullanın. Şifresiz HTTP POST formlarından kaçının."
    },
    "FTP Kimlik Bilgisi (Kullanıcı Adı)": {
      explanation: "Güvensiz FTP protokolü üzerinden ağda açık metin bir kullanıcı adı yakalandı.",
      remediation: "FTP yerine şifreli SFTP veya FTPS protokolünü kullanın."
    },
    "FTP Kimlik Bilgisi (Şifre)": {
      explanation: "Güvensiz FTP protokolü üzerinden şifreniz ağda açık metin (şifrelenmemiş) olarak yakalandı. Herkes şifrenizi ele geçirebilir.",
      remediation: "Derhal şifrenizi değiştirin ve bir daha asla şifresiz FTP kullanmayın. SFTP/FTPS kullanımına geçin."
    },
    "Port Taraması Algılandı": {
      explanation: "Bir cihaz kısa süre içinde bilgisayarınızdaki çok sayıda kapıya (porta) dokunarak hangi servislerin çalıştığını ve açık kapı olup olmadığını bulmaya çalışmış.",
      remediation: "Saldırganın IP adresini (yerel ağdaysa) tespit edin. Bilgisayarınızın güvenlik duvarında (Windows Defender Firewall) gereksiz portları kapatın ve gizli modda (Stealth) kalın."
    },
    "DoS / Trafik Flood Saldırı Şüphesi": {
      explanation: "Bir bilgisayar ağ geçidine veya sizin cihazınıza saniyede yüzlerce paket göndererek hattınızı tıkamaya ve internetinizi çökertmeye çalışıyor.",
      remediation: "Saldırıyı yapan yerel IP ise ağdan bağlantısını kesin (modem arayüzünden engelleyin). İnternetten geliyorsa IPS/IDS sistemlerinden o IP'yi kara listeye alın."
    },
    "SYN Flood (Hizmet Dışı Bırakma) Şüphesi": {
      explanation: "Hedef sunucunun hafızasını tüketmek ve internetini çökertmek amacıyla saniyede çok sayıda yarım kalmış TCP SYN (bağlantı başlama) paketi gönderiliyor.",
      remediation: "Sunucuda SYN cookies özelliğini aktif edin, güvenlik duvarında (Firewall) saniyede kabul edilecek maksimum SYN limitini (rate limiting) yapılandırın."
    },
    "Şüpheli/Güvensiz Port İletişimi": {
      explanation: "Metasploit varsayılan portu (4444), IRC (6667 botnet kanalı) veya şifresiz eski protokoller (Telnet - 23) üzerinden bir bağlantı kuruldu. Cihazınıza sızılmış veya güvensiz veri aktarılıyor olabilir.",
      remediation: "Bu portu kullanan arka plan işlemlerini (process) kontrol edin. Windows Görev Yöneticisi'nden şüpheli uygulamaları sonlandırın. Telnet yerine SSH (Port 22) kullanın."
    },
    "Şüpheli/Güvensiz Port İletişimi (UDP)": {
      explanation: "Zararlı olabilecek güvensiz bir port (örneğin Telnet/Metasploit) üzerinden UDP paket trafiği algılandı.",
      remediation: "Güvenlik duvarınızdan o portu engelleyin ve bilgisayarınızda virüs taraması gerçekleştirin."
    }
  };

  // 2. Meta Bilgileri Doldur
  document.getElementById('meta-filename').textContent = data.dosya_adi || 'Bilinmeyen';
  document.getElementById('meta-packets').textContent = data.paket_sayisi || 0;
  
  const alertsCount = data.alerts ? data.alerts.length : 0;
  const metaAlerts = document.getElementById('meta-alerts');
  metaAlerts.textContent = alertsCount;
  if (alertsCount > 0) {
    metaAlerts.style.color = 'var(--cyber-danger)';
  } else {
    metaAlerts.style.color = 'var(--cyber-success)';
  }

  // 3. Güvenlik Alarmlarını Render Et
  const alertsContainer = document.getElementById('alerts-container');
  if (alertsContainer) {
    if (!data.alerts || data.alerts.length === 0) {
      alertsContainer.innerHTML = `
        <div class="empty-alerts">
          <span style="font-size: 2.2rem;">🛡️</span>
          <h3 style="font-weight: 700; color: var(--cyber-success);">Harika! Siber Tehdit Saptanmadı</h3>
          <p style="font-size: 0.9rem; color: var(--text-muted);">
            Ağ trafiği üzerinde yapılan kural tabanlı analizlerde herhangi bir anomali veya saldırı izine rastlanmadı.
          </p>
        </div>
      `;
    } else {
      // Alarmları önem derecesine göre sırala (CRITICAL > HIGH > MEDIUM > LOW > INFO)
      const severityWeight = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 };
      const sortedAlerts = [...data.alerts].sort((a, b) => {
        return (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
      });

      alertsContainer.innerHTML = '';
      
      const criticalGroup = sortedAlerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH');
      const mediumGroup = sortedAlerts.filter(a => a.severity === 'MEDIUM');
      const lowGroup = sortedAlerts.filter(a => a.severity === 'LOW' || a.severity === 'INFO');

      const renderAlertGroup = (title, alerts, badgeClass) => {
        if (alerts.length === 0) return;
        
        const groupWrapper = document.createElement('div');
        groupWrapper.className = 'alerts-tree-group';
        
        const groupHeader = document.createElement('div');
        groupHeader.className = 'alerts-tree-group-header';
        groupHeader.innerHTML = `
          <span style="display:flex; align-items:center; gap:8px; font-weight:700;">
            <span class="tree-toggle-icon">▶</span> ${title}
          </span>
          <span class="alert-badge ${badgeClass}" style="font-size:0.75rem;">${alerts.length} Tehdit</span>
        `;
        
        const groupContent = document.createElement('div');
        groupContent.className = 'alerts-tree-group-content';
        groupContent.style.display = 'none'; // Default closed
        
        alerts.forEach((alert, i) => {
          const item = document.createElement('div');
          item.className = `alert-item ${alert.severity.toLowerCase()}`;
          
          let flowInfo = '';
          if (alert.src_ip !== '-' || alert.dst_ip !== '-') {
            const safeSrc = escapeHtml(alert.src_ip);
            const safeDst = escapeHtml(alert.dst_ip);
            const safeProto = escapeHtml(alert.proto);
            flowInfo = `<span class="alert-flow" data-ip-src="${safeSrc}">${safeSrc} &rarr; ${safeDst} (${safeProto})</span>`;
          }

          const safePacketIndex = escapeHtml(alert.packet_index);
          const pktIndexLink = alert.packet_index
            ? `<a href="#" class="pkt-link" data-index="${safePacketIndex}" style="color: var(--cyber-primary); font-weight: 600; text-decoration: underline;">Paket #${safePacketIndex}</a>`
            : 'Genel Analiz';

          let explainButton = '';
          let explainBox = '';
          const glossaryItem = threatGlossary[alert.title];
          if (glossaryItem) {
            const uniqueId = `explain-${alert.packet_index || 'genel'}-${i}-${badgeClass}`;
            explainButton = `
              <button class="btn-explain btn-toggle-explain" data-target="${uniqueId}" style="margin-top: 8px;">
                ℹ️ Bu Ne Anlama Gelir?
              </button>
            `;
            explainBox = `
              <div class="explanation-box" id="${uniqueId}">
                <div class="explanation-title">🔍 Tehdit Açıklaması</div>
                <div style="color: var(--text-muted);">${glossaryItem.explanation}</div>
                <div class="remediation-title">🛡️ Ne Yapmalıyım? (Çözüm Önerisi)</div>
                <div style="color: var(--text-muted);">${glossaryItem.remediation}</div>
              </div>
            `;
          }

          item.innerHTML = `
            <div class="alert-header">
              <span class="alert-title" style="color: var(--text-main); font-weight: 700;">${escapeHtml(alert.title)}</span>
              <span class="alert-badge ${alert.severity.toLowerCase()}" style="font-size:0.6rem; padding: 1px 6px;">${escapeHtml(alert.severity)}</span>
            </div>
            <div class="alert-desc">${escapeHtml(alert.description)}</div>
            ${explainButton}
            ${explainBox}
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px; border-top: 1px solid rgba(48,54,61,0.2); padding-top: 6px;">
              ${flowInfo}
              <span style="font-size: 0.72rem; color: var(--text-muted);">${pktIndexLink}</span>
            </div>
          `;
          groupContent.appendChild(item);
        });
        
        groupHeader.addEventListener('click', () => {
          const isExpanded = groupContent.style.display === 'flex';
          groupContent.style.display = isExpanded ? 'none' : 'flex';
          groupHeader.querySelector('.tree-toggle-icon').style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(90deg)';
        });
        
        // Default expand critical group
        if (badgeClass === 'critical') {
          groupContent.style.display = 'flex';
          groupHeader.querySelector('.tree-toggle-icon').style.transform = 'rotate(90deg)';
        }
        
        groupWrapper.appendChild(groupHeader);
        groupWrapper.appendChild(groupContent);
        alertsContainer.appendChild(groupWrapper);
      };

      renderAlertGroup('🚨 YÜKSEK SEVİYELİ TEHDİTLER (Kritik)', criticalGroup, 'critical');
      renderAlertGroup('⚠️ ORTA SEVİYELİ ANOMALİLER', mediumGroup, 'medium');
      renderAlertGroup('ℹ️ DÜŞÜK SEVİYELİ UYARILAR & BİLGİ', lowGroup, 'low');

      // Paket numarasına tıklama olayı (ilgili pakete odaklanma)
      alertsContainer.querySelectorAll('.pkt-link').forEach(link => {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          const targetIndex = parseInt(link.getAttribute('data-index'));
          focusOnPacket(targetIndex);
        });
      });
      
      // Dinamik açılan açıklamaları bağla
      alertsContainer.querySelectorAll('.btn-toggle-explain').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetId = btn.getAttribute('data-target');
          const box = document.getElementById(targetId);
          if (box) {
            const isHidden = box.style.display === 'none' || box.style.display === '';
            box.style.display = isHidden ? 'block' : 'none';
            btn.innerHTML = isHidden ? 'ℹ️ Açıklamayı Kapat' : 'ℹ️ Bu Ne Anlama Gelir?';
          }
        });
      });
    }
  }

  // 4. AI Raporunu Render Et
  const aiSection = document.getElementById('ai-report-section');
  const aiBody = document.getElementById('ai-report-body');
  if (data.use_ai && data.ai_report && aiSection && aiBody) {
    aiSection.style.display = 'block';
    // AI raporu, paket ozetlerinden (dolayisiyla saldirgan kontrolundeki ag
    // trafiginden) alintilar iceriyor olabilir; markdown->HTML ciktisini
    // basmadan once mutlaka DOMPurify ile temizle.
    if (typeof marked !== 'undefined') {
      const rawHtml = marked.parse(data.ai_report);
      aiBody.innerHTML = (typeof DOMPurify !== 'undefined') ? DOMPurify.sanitize(rawHtml) : escapeHtml(data.ai_report);
    } else {
      aiBody.innerHTML = `<pre class="terminal">${escapeHtml(data.ai_report)}</pre>`;
    }
  }

  // 5. Grafikleri Çiz (Chart.js)
  const stats = data.stats || {};

  // Donut Grafik: Protokol Dağılımı
  const protoCanvas = document.getElementById('chart-protocols');
  if (protoCanvas && stats.protocol_counts) {
    const protoLabels = Object.keys(stats.protocol_counts);
    const protoValues = Object.values(stats.protocol_counts);
    
    const protoColors = {
      'TCP': 'rgba(0, 240, 255, 0.85)',
      'UDP': 'rgba(57, 255, 20, 0.85)',
      'ARP': 'rgba(255, 221, 0, 0.85)',
      'DNS': 'rgba(189, 0, 255, 0.85)',
      'HTTP': 'rgba(255, 0, 85, 0.85)',
      'TLS': 'rgba(255, 0, 183, 0.85)',
      'diger': 'rgba(139, 148, 158, 0.85)'
    };
    const bgColors = protoLabels.map(label => protoColors[label] || 'rgba(111, 87, 255, 0.85)');

    new Chart(protoCanvas, {
      type: 'doughnut',
      data: {
        labels: protoLabels,
        datasets: [{
          data: protoValues,
          backgroundColor: bgColors,
          borderWidth: 1.5,
          borderColor: '#020508'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        animation: {
          duration: 1800,
          animateRotate: true,
          animateScale: true,
          easing: 'easeOutQuart'
        },
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#c9d1d9', font: { family: 'JetBrains Mono', size: 10 } }
          }
        }
      }
    });
  }

  // Bar Grafik: En Aktif Konuşan IP'ler (Top 5)
  const talkersCanvas = document.getElementById('chart-talkers');
  if (talkersCanvas && stats.talker_counts) {
    const sortedTalkers = Object.entries(stats.talker_counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const talkerLabels = sortedTalkers.map(item => item[0]);
    const talkerValues = sortedTalkers.map(item => item[1]);

    const ctxTalkers = talkersCanvas.getContext('2d');
    const gradTalkers = ctxTalkers.createLinearGradient(0, 0, 350, 0);
    gradTalkers.addColorStop(0, 'rgba(0, 240, 255, 0.05)');
    gradTalkers.addColorStop(1, 'rgba(0, 240, 255, 0.85)');

    new Chart(talkersCanvas, {
      type: 'bar',
      data: {
        labels: talkerLabels,
        datasets: [{
          label: 'Paket Sayısı',
          data: talkerValues,
          backgroundColor: gradTalkers,
          borderColor: '#00f0ff',
          borderWidth: 1.5,
          borderRadius: 3,
          barThickness: 10
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 1600,
          easing: 'easeOutElastic',
          delay: (context) => context.dataIndex * 150
        },
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { grid: { color: 'rgba(0, 255, 102, 0.04)' }, ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 9 } } },
          y: { grid: { display: false }, ticks: { color: '#e8ffe2', font: { family: 'JetBrains Mono', size: 10 } } }
        }
      }
    });
  }

  // Bar Grafik: En Çok Hedeflenen Portlar (Top 5)
  const portsCanvas = document.getElementById('chart-ports');
  if (portsCanvas && stats.port_counts) {
    const sortedPorts = Object.entries(stats.port_counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const portLabels = sortedPorts.map(item => item[0]);
    const portValues = sortedPorts.map(item => item[1]);

    const ctxPorts = portsCanvas.getContext('2d');
    const gradPorts = ctxPorts.createLinearGradient(0, 0, 0, 180);
    gradPorts.addColorStop(0, 'rgba(255, 0, 183, 0.85)');
    gradPorts.addColorStop(1, 'rgba(255, 0, 183, 0.05)');

    new Chart(portsCanvas, {
      type: 'bar',
      data: {
        labels: portLabels,
        datasets: [{
          label: 'Paket Sayısı',
          data: portValues,
          backgroundColor: gradPorts,
          borderColor: '#ff00b7',
          borderWidth: 1.5,
          borderRadius: 3,
          barThickness: 24
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 1600,
          easing: 'easeOutElastic',
          delay: (context) => context.dataIndex * 120
        },
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#e8ffe2', font: { family: 'JetBrains Mono', size: 10 } } },
          y: { grid: { color: 'rgba(0, 255, 102, 0.04)' }, ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 9 } } }
        }
      }
    });
  }

  // 6. vis.js İnteraktif Ağ Haritası (Topoloji) Çizimi
  const mapContainer = document.getElementById('network-topology-map');
  if (mapContainer && data.packets && typeof vis !== 'undefined') {
    const nodesMap = new Map();
    const edgesMap = new Map();
    
    // Alarmlardaki riskli IP'leri toplayalım
    const suspiciousIPs = new Set();
    if (data.alerts) {
      data.alerts.forEach(alert => {
        if (alert.src_ip && alert.src_ip !== '-') suspiciousIPs.add(alert.src_ip);
        if (alert.dst_ip && alert.dst_ip !== '-') suspiciousIPs.add(alert.dst_ip);
      });
    }

    // Paketlerden bağlantıları ve IP'leri çıkar
    data.packets.forEach(pkt => {
      // Standard IP match: [1] TCP  192.168.1.10:4444 -> 10.0.0.1:80 or 192.168.1.1:-
      const match = pkt.summary.match(/^\[\d+\]\s+[A-Za-z0-9\-\/]+\s+([0-9\.\:\-]+)\s+->\s+([0-9\.\:\-]+)/);
      if (match) {
        const srcIP = match[1].split(':')[0];
        const dstIP = match[2].split(':')[0];
        
        nodesMap.set(srcIP, (nodesMap.get(srcIP) || 0) + 1);
        nodesMap.set(dstIP, (nodesMap.get(dstIP) || 0) + 1);
        
        const edgeKey = srcIP < dstIP ? `${srcIP}_${dstIP}` : `${dstIP}_${srcIP}`;
        edgesMap.set(edgeKey, (edgesMap.get(edgeKey) || 0) + 1);
      } else {
        // ARP match: [1] ARP  192.168.1.1 who-has 192.168.1.254
        const arpMatch = pkt.summary.match(/^\[\d+\]\s+ARP\s+([0-9\.]+)\s+(who-has|is-at)\s+([0-9\.]+)/);
        if (arpMatch) {
          const srcIP = arpMatch[1];
          const dstIP = arpMatch[3];
          
          nodesMap.set(srcIP, (nodesMap.get(srcIP) || 0) + 1);
          nodesMap.set(dstIP, (nodesMap.get(dstIP) || 0) + 1);
          
          const edgeKey = srcIP < dstIP ? `${srcIP}_${dstIP}` : `${dstIP}_${srcIP}`;
          edgesMap.set(edgeKey, (edgesMap.get(edgeKey) || 0) + 1);
        }
      }
    });

    // vis-network'ün fizik motoru birkaç bin node'dan sonra ciddi yavaşlıyor
    // ve tarayıcı sekmesini kilitleyebiliyor (buyuk pcap'lerde binlerce
    // benzersiz IP olabilir). Bu yuzden haritayi en yogun/supheli ilk
    // TOP_N_TOPOLOGY_NODES IP ile siniirliyoruz; supheli IP'ler trafik
    // hacmine bakilmaksizin her zaman haritada kalir.
    const TOP_N_TOPOLOGY_NODES = 150;
    let allowedIPs = new Set(nodesMap.keys());
    let topologyTruncated = false;

    if (nodesMap.size > TOP_N_TOPOLOGY_NODES) {
      topologyTruncated = true;
      const ranked = Array.from(nodesMap.entries()).sort((a, b) => {
        const aSuspicious = suspiciousIPs.has(a[0]) ? 1 : 0;
        const bSuspicious = suspiciousIPs.has(b[0]) ? 1 : 0;
        if (aSuspicious !== bSuspicious) return bSuspicious - aSuspicious;
        return b[1] - a[1];
      });
      allowedIPs = new Set(ranked.slice(0, TOP_N_TOPOLOGY_NODES).map(([ip]) => ip));
    }

    const topologyDesc = document.getElementById('topology-desc');
    if (topologyDesc) {
      topologyDesc.textContent = topologyTruncated
        ? `IP düğümleri ve akış trafiği modellenmiştir. En yoğun ve şüpheli ${TOP_N_TOPOLOGY_NODES} IP gösteriliyor (toplam ${nodesMap.size} benzersiz IP tespit edildi). Bilgi edinmek için düğümlerin üzerine gelin.`
        : 'IP düğümleri ve akış trafiği modellenmiştir. Düğümler üzerinde parlayan neon gölgeler cihaz tipini ve risk durumunu temsil eder. Bilgi edinmek için düğümlerin üzerine gelin.';
    }

    const nodes = [];
    const edges = [];

    // Node ayarlarını eşleştir
    nodesMap.forEach((count, ip) => {
      if (!allowedIPs.has(ip)) return;
      const isSuspicious = suspiciousIPs.has(ip);
      const isPrivate = ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip.startsWith('127.');
      
      let color = {
        background: '#010508',
        border: '#00ff66',
        highlight: { background: '#00ff66', border: '#39ff14' },
        hover: { background: 'rgba(0, 255, 102, 0.15)', border: '#39ff14' }
      };
      
      let label = ip;
      let shadowGlow = {};
      let shape = 'dot';

      if (isSuspicious) {
        // Tehdit içeren riskli cihaz (Laser Red Warning Triangle)
        color = {
          background: 'rgba(255, 0, 85, 0.1)',
          border: '#ff0055',
          highlight: { background: '#ff0055', border: '#ff5588' },
          hover: { background: 'rgba(255, 0, 85, 0.2)', border: '#ff5588' }
        };
        shadowGlow = { enabled: true, color: 'rgba(255, 0, 85, 0.7)', size: 18, x: 0, y: 0 };
        label += '\n⚠️ [RISK]';
        shape = 'triangle';
      } else if (!isPrivate) {
        // Dış İnternet IP'si (Neon Emerald Star)
        color = {
          background: 'rgba(0, 255, 183, 0.05)',
          border: '#00ffb7',
          highlight: { background: '#00ffb7', border: '#66ffd8' },
          hover: { background: 'rgba(0, 255, 183, 0.15)', border: '#66ffd8' }
        };
        shadowGlow = { enabled: true, color: 'rgba(0, 255, 183, 0.5)', size: 15, x: 0, y: 0 };
        shape = 'star';
      } else if (ip.endsWith('.1') || ip.endsWith('.254')) {
        // Ağ Geçidi / Gateway (Laser Green Diamond)
        color = {
          background: 'rgba(0, 255, 102, 0.05)',
          border: '#00ff66',
          highlight: { background: '#00ff66', border: '#39ff14' },
          hover: { background: 'rgba(0, 255, 102, 0.15)', border: '#39ff14' }
        };
        shadowGlow = { enabled: true, color: 'rgba(0, 255, 102, 0.65)', size: 15, x: 0, y: 0 };
        label += '\n⚡ GW';
        shape = 'diamond';
      } else {
        // Yerel Cihaz (Laser Green Dot)
        color = {
          background: 'rgba(0, 255, 102, 0.05)',
          border: '#00ff66',
          highlight: { background: '#00ff66', border: '#39ff14' },
          hover: { background: 'rgba(0, 255, 102, 0.15)', border: '#39ff14' }
        };
        shadowGlow = { enabled: true, color: 'rgba(0, 255, 102, 0.55)', size: 15, x: 0, y: 0 };
        shape = 'dot';
      }

      // Sade ve Sorunsuz Düz Metin Tooltip Yapılandırması
      let typeLabelText = "Yerel Cihaz";
      if (!isPrivate) {
        typeLabelText = "Dış İnternet";
      } else if (ip.endsWith('.1') || ip.endsWith('.254')) {
        typeLabelText = "Ağ Geçidi / Gateway";
      }
      
      const nodeTitle = `${ip}\n---\nTür: ${typeLabelText}\nTrafik: ${count} Paket\nKonum: ${isPrivate ? 'Yerel Ağ (LAN)' : 'Dış Dünya (Sorgulanıyor...)'}`;

      nodes.push({
        id: ip,
        label: label,
        shape: shape,
        size: 15 + Math.min(count * 0.2, 25),
        color: color,
        shadow: shadowGlow,
        title: nodeTitle,
        font: { color: '#e8ffe2', face: 'JetBrains Mono', size: 11 }
      });
    });

    edgesMap.forEach((count, key) => {
      const [from, to] = key.split('_');
      if (!allowedIPs.has(from) || !allowedIPs.has(to)) return;
      edges.push({
        from: from,
        to: to,
        width: 1 + Math.min(count * 0.1, 8),
        color: { color: 'rgba(0, 255, 102, 0.15)', highlight: 'rgba(0, 255, 102, 0.55)' },
        smooth: { type: 'continuous', roundness: 0.5 }
      });
    });

    visData = {
      nodes: new vis.DataSet(nodes),
      edges: new vis.DataSet(edges)
    };

    const options = {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -55,
          centralGravity: 0.015,
          springLength: 110,
          springConstant: 0.08,
          damping: 0.4
        },
        stabilization: {
          enabled: true,
          iterations: 150,
          updateInterval: 25
        }
      },
      edges: {
        arrows: {
          to: { enabled: true, scaleFactor: 0.4 }
        }
      },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
        dragView: true,
        zoomSpeed: 0.15
      }
    };

    network = new vis.Network(mapContainer, visData, options);
  }

  // 7. IP Coğrafi Konum (IP Geolocation) ve Bayrak Eşleme
  if (stats.talker_counts) {
    const talkers = Object.entries(stats.talker_counts)
      .sort((a, b) => b[1] - a[1]);

    const externalTalkers = talkers.filter(item => {
      const ip = item[0];
      return !(ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip.startsWith('127.') || ip === 'diger');
    });

    externalTalkers.slice(0, 3).forEach(async (item) => {
      const ip = item[0];
      try {
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        if (response.ok) {
          const geoData = await response.json();
          if (geoData.country_name) {
            const country = geoData.country_name;
            const flag = geoData.country_code ? geoData.country_code.toLowerCase() : '';
            updateIPLabels(ip, country, flag);
          }
        }
      } catch (err) {
        console.warn(`IP Geolocation fetch error for ${ip}:`, err);
      }
    });
  }

  function updateIPLabels(ip, country, flag) {
    const getFlagEmoji = (countryCode) => {
      if (!countryCode) return '🏳️';
      const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt(0));
      return String.fromCodePoint(...codePoints);
    };

    const emoji = getFlagEmoji(flag);
    // country, ucuncu parti bir servisten (ipapi.co) geliyor - guvenilmeyen
    // dis kaynak, innerHTML'e yazilmadan once escape edilmeli.
    const geoText = ` ${emoji} (${escapeHtml(country)})`;

    // Alarmlardaki IP'leri güncelle
    document.querySelectorAll('.alert-flow').forEach(el => {
      if (el.getAttribute('data-ip-src') === ip) {
        el.innerHTML = el.innerHTML.replace(escapeHtml(ip), `${escapeHtml(ip)}${geoText}`);
      }
    });

    // Harita üzerindeki düğümü güncelle
    if (visData && visData.nodes) {
      const node = visData.nodes.get(ip);
      if (node) {
        const updatedLabel = `${ip}\n${emoji} ${country}`;
        const updatedTitle = node.title
          .replace('Sorgulanıyor...', `${emoji} ${country}`)
          .replace('🌐 Dış İnternet', `🌐 Dış İnternet (${country})`);
        
        visData.nodes.update({
          id: ip,
          label: updatedLabel,
          title: updatedTitle
        });
      }
    }
  }

  // 8. Rapor Dışa Aktarma (Export) Kontrolleri
  const exportBtn = document.getElementById('btn-export-dropdown');
  const dropdownMenu = document.getElementById('export-dropdown-menu');
  if (exportBtn && dropdownMenu) {
    exportBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isVisible = dropdownMenu.style.display === 'block';
      dropdownMenu.style.display = isVisible ? 'none' : 'block';
    });
    
    document.addEventListener('click', () => {
      dropdownMenu.style.display = 'none';
    });
  }

  // JSON İndir
  const exportJson = document.getElementById('export-json');
  if (exportJson) {
    exportJson.addEventListener('click', (e) => {
      e.preventDefault();
      const cleanFilename = data.dosya_adi.replace(/[^a-zA-Z0-9]/g, '_');
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
      const dlAnchor = document.createElement('a');
      dlAnchor.setAttribute("href", dataStr);
      dlAnchor.setAttribute("download", `ag_raporu_${cleanFilename}.json`);
      document.body.appendChild(dlAnchor);
      dlAnchor.click();
      dlAnchor.remove();
    });
  }

  // AI Raporu İndir
  const exportMd = document.getElementById('export-md');
  if (exportMd) {
    exportMd.addEventListener('click', (e) => {
      e.preventDefault();
      if (!data.use_ai || !data.ai_report) {
        alert("Bu analizde yapay zeka siber güvenlik raporu oluşturulmamış.");
        return;
      }
      const cleanFilename = data.dosya_adi.replace(/[^a-zA-Z0-9]/g, '_');
      const dataStr = "data:text/markdown;charset=utf-8," + encodeURIComponent(data.ai_report);
      const dlAnchor = document.createElement('a');
      dlAnchor.setAttribute("href", dataStr);
      dlAnchor.setAttribute("download", `ai_raporu_${cleanFilename}.md`);
      document.body.appendChild(dlAnchor);
      dlAnchor.click();
      dlAnchor.remove();
    });
  }

  // PDF İndir (Yazdır)
  const exportPdf = document.getElementById('export-pdf');
  if (exportPdf) {
    exportPdf.addEventListener('click', (e) => {
      e.preventDefault();
      window.print();
    });
  }

  // --- Siber Güvenlik Katman Kılavuzu ve Ağaç Yapısı Mantığı ---
  const layerExplanations = {
    ethernet: {
      title: "Katman 2 - Ethernet Nedir?",
      text: "Ethernet katmanı, yerel ağınızdaki (örneğin evinizdeki Wi-Fi veya kablolu ağ) cihazların birbirlerine veri gönderebilmesi için kullandıkları fiziksel ve donanımsal el sıkışma katmanıdır. Burada bilgisayarların benzersiz fabrikasyon kimliği olan <strong>MAC Adresleri</strong> (örn: 00:1A:2B:3C:4D:5E) kullanılır."
    },
    ip: {
      title: "Katman 3 - IP (İnternet Protokolü) Nedir?",
      text: "Ağ katmanı, paketlerin internetteki milyarlarca bilgisayar arasından doğru hedef adrese yönlendirilmesini (routing) sağlayan sanal adresleme katmanıdır. <strong>IPv4</strong> (örn: 192.168.1.5) ve yeni nesil <strong>IPv6</strong> adresleri bu katmanda çalışır. İnternet yolculuğu bu katmandaki yönlendirmelerle gerçekleşir."
    },
    transport: {
      title: "Katman 4 - Taşıma Katmanı Nedir?",
      text: "Taşıma katmanı, iki bilgisayar arasındaki veri akışının kurallarını ve kalitesini belirler. <strong>TCP</strong> (hata kontrolü yapan, paketlerin sırasını ve ulaştığını garanti eden kararlı protokol) veya <strong>UDP</strong> (hız odaklı olan, paketlerin ulaşıp ulaşmadığını umursamayan, canlı yayın ve oyunlarda kullanılan protokol) bu katmanda port numaralarıyla çalışır."
    },
    application: {
      title: "Katman 5 - Uygulama Katmanı Nedir?",
      text: "Kullanıcıların doğrudan etkileşime girdiği web tarayıcıları, e-posta istemcileri ve uygulamalar tarafından üretilen şifreli/şifresiz verilerin (HTTP web sayfaları, DNS sorguları, TLS güvenli SSL el sıkışmaları) taşındığı en üst katmandır. Paketlerin asıl yükünü (payload) barındırır."
    }
  };

  function showLayerExplanationModal(layerKey) {
    const info = layerExplanations[layerKey];
    if (!info) return;
    
    let modal = document.getElementById('security-education-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'security-education-modal';
      modal.style.position = 'fixed';
      modal.style.top = '0';
      modal.style.left = '0';
      modal.style.width = '100vw';
      modal.style.height = '100vh';
      modal.style.backgroundColor = 'rgba(3, 7, 18, 0.85)';
      modal.style.backdropFilter = 'blur(6px)';
      modal.style.zIndex = '9999';
      modal.style.display = 'flex';
      modal.style.justifyContent = 'center';
      modal.style.alignItems = 'center';
      modal.style.opacity = '0';
      modal.style.transition = 'opacity 0.2s ease-out';
      
      modal.innerHTML = `
        <div class="card" style="width: 90%; max-width: 480px; padding: 24px; position: relative; margin: 0; border: 1px solid var(--cyber-primary); box-shadow: 0 0 25px rgba(56,139,253,0.3);">
          <h2 id="edu-modal-title" style="margin-bottom: 12px; font-size: 1.15rem; color: #fff; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 8px;"></h2>
          <p id="edu-modal-text" style="font-size: 0.85rem; line-height: 1.6; color: var(--text-muted); margin-bottom: 20px;"></p>
          <button id="edu-modal-close" class="btn btn-primary" style="padding: 10px 20px; font-size: 0.85rem; width: auto; display: block; margin-left: auto;">Anladım, Kapat</button>
        </div>
      `;
      document.body.appendChild(modal);
    }
    
    document.getElementById('edu-modal-title').textContent = info.title;
    document.getElementById('edu-modal-text').innerHTML = info.text;
    
    modal.style.display = 'flex';
    setTimeout(() => { modal.style.opacity = '1'; }, 50);
    
    const closeBtn = document.getElementById('edu-modal-close');
    closeBtn.onclick = () => {
      modal.style.opacity = '0';
      setTimeout(() => { modal.style.display = 'none'; }, 200);
    };
  }

  function buildPacketTreeHTML(pkt) {
    const parts = pkt.summary.split('|');
    const header = parts[0];
    const details = parts.slice(1);
    
    let proto = 'Other';
    let src = '-';
    let dst = '-';
    const match = header.match(/^\[\d+\]\s+([A-Za-z0-9\-]+)\s+([^\s]+)\s+->\s+([^\s]+)/);
    if (match) {
      proto = match[1].trim();
      src = match[2].trim();
      dst = match[3].trim();
    }
    
    let html = `<div class="packet-tree-container" style="display: flex; flex-direction: column; gap: 8px;">`;
    
    // Katman 2: Ethernet
    html += `
      <div class="tree-node">
        <div class="tree-header btn-tree-toggle">
          <span class="tree-toggle-icon">▶</span>
          <span style="font-weight:600; color:var(--text-main); display:inline-flex; align-items:center; gap:6px;"><i data-lucide="layers" style="width:12px;height:12px;color:var(--cyber-primary);"></i> Katman 2 - Veri Bağı Katmanı (Ethernet)</span>
          <button class="btn-info-circle" data-info="ethernet" title="Açıklama"><i data-lucide="help-circle" style="width:12px;height:12px;"></i></button>
        </div>
        <div class="tree-children">
          <div class="tree-leaf"><span>Protokol:</span><span class="tree-leaf-value">Ethernet II (IEEE 802.3)</span></div>
          <div class="tree-leaf"><span>Donanım Adresleme:</span><span class="tree-leaf-value">MAC Adresleri</span></div>
        </div>
      </div>
    `;

    // Katman 3: IP
    const isIPv6 = src.includes(':') && !src.includes('.') && src.split(':').length > 2;
    const ipProto = isIPv6 ? 'IPv6' : 'IPv4';
    const srcIP = src.split(':')[0];
    const dstIP = dst.split(':')[0];
    
    html += `
      <div class="tree-node">
        <div class="tree-header btn-tree-toggle">
          <span class="tree-toggle-icon">▶</span>
          <span style="font-weight:600; color:var(--text-main); display:inline-flex; align-items:center; gap:6px;"><i data-lucide="globe" style="width:12px;height:12px;color:var(--cyber-primary);"></i> Katman 3 - Ağ Katmanı (${ipProto})</span>
          <button class="btn-info-circle" data-info="ip" title="Açıklama"><i data-lucide="help-circle" style="width:12px;height:12px;"></i></button>
        </div>
        <div class="tree-children">
          <div class="tree-leaf"><span>Protokol Sürümü:</span><span class="tree-leaf-value">${ipProto}</span></div>
          <div class="tree-leaf"><span>Kaynak IP Adresi:</span><span class="tree-leaf-value">${escapeHtml(srcIP)}</span></div>
          <div class="tree-leaf"><span>Hedef IP Adresi:</span><span class="tree-leaf-value">${escapeHtml(dstIP)}</span></div>
          <div class="tree-leaf"><span>Yönlendirme Protokolü:</span><span class="tree-leaf-value">${escapeHtml(proto)}</span></div>
        </div>
      </div>
    `;

    // Katman 4: Taşıma (TCP/UDP/ARP)
    let l4Content = '';
    if (proto === 'TCP' || proto === 'UDP') {
      const srcPort = src.split(':')[1] || '-';
      const dstPort = dst.split(':')[1] || '-';
      l4Content = `
        <div class="tree-leaf"><span>Taşıma Protokolü:</span><span class="tree-leaf-value">${escapeHtml(proto)}</span></div>
        <div class="tree-leaf"><span>Kaynak Portu (Gönderen):</span><span class="tree-leaf-value">${escapeHtml(srcPort)}</span></div>
        <div class="tree-leaf"><span>Hedef Portu (Alıcı):</span><span class="tree-leaf-value">${escapeHtml(dstPort)}</span></div>
      `;
    } else if (proto === 'ARP') {
      l4Content = `
        <div class="tree-leaf"><span>Ağ Protokolü:</span><span class="tree-leaf-value">ARP (Address Resolution)</span></div>
        <div class="tree-leaf"><span>İşlem Mantığı:</span><span class="tree-leaf-value">MAC adresi çözümleme sorgusu</span></div>
      `;
    } else {
      l4Content = `<div class="tree-leaf"><span>Protokol:</span><span class="tree-leaf-value">${escapeHtml(proto)}</span></div>`;
    }
    
    html += `
      <div class="tree-node">
        <div class="tree-header btn-tree-toggle">
          <span class="tree-toggle-icon">▶</span>
          <span style="font-weight:600; color:var(--text-main); display:inline-flex; align-items:center; gap:6px;"><i data-lucide="zap" style="width:12px;height:12px;color:var(--cyber-primary);"></i> Katman 4 - Taşıma Katmanı (${proto})</span>
          <button class="btn-info-circle" data-info="transport" title="Açıklama"><i data-lucide="help-circle" style="width:12px;height:12px;"></i></button>
        </div>
        <div class="tree-children">
          ${l4Content}
        </div>
      </div>
    `;

    // Katman 5: Uygulama
    let appContent = '';
    details.forEach(detail => {
      const trimmed = detail.trim();
      const safeTrimmed = escapeHtml(trimmed);
      if (trimmed.startsWith('DNS')) {
        appContent += `<div class="tree-leaf"><span style="color: #c084fc;">DNS Çözümleme:</span><span class="tree-leaf-value">${safeTrimmed}</span></div>`;
      } else if (trimmed.startsWith('HTTP')) {
        appContent += `<div class="tree-leaf"><span style="color: #ff983f;">HTTP İsteği:</span><span class="tree-leaf-value">${safeTrimmed}</span></div>`;
      } else if (trimmed.startsWith('TLS')) {
        appContent += `<div class="tree-leaf"><span style="color: #f472b6;">TLS Şifreli Bağlantı:</span><span class="tree-leaf-value">${safeTrimmed}</span></div>`;
      } else {
        appContent += `<div class="tree-leaf"><span>Veri Detayı (Payload):</span><span class="tree-leaf-value">${safeTrimmed}</span></div>`;
      }
    });

    if (appContent === '') {
      appContent = `<div class="tree-leaf"><span>Uygulama Detayı:</span><span class="tree-leaf-value">Bu paket için ek üst düzey veri ayrıştırılmadı.</span></div>`;
    }

    html += `
      <div class="tree-node">
        <div class="tree-header btn-tree-toggle">
          <span class="tree-toggle-icon">▶</span>
          <span style="font-weight:600; color:var(--text-main); display:inline-flex; align-items:center; gap:6px;"><i data-lucide="file-text" style="width:12px;height:12px;color:var(--cyber-primary);"></i> Katman 5 - Uygulama Katmanı (Payload)</span>
          <button class="btn-info-circle" data-info="application" title="Açıklama"><i data-lucide="help-circle" style="width:12px;height:12px;"></i></button>
        </div>
        <div class="tree-children">
          ${appContent}
        </div>
      </div>
    `;
    
    html += `</div>`;
    return html;
  }

  // 9. Sayfalı ve Aranabilir Paket Tablosu
  let currentPage = 1;
  const pageSize = 20;
  let filteredPackets = data.packets ? [...data.packets] : [];
  
  const tableBody = document.getElementById('packet-table-body');
  const searchInput = document.getElementById('table-search');
  const prevBtn = document.getElementById('btn-prev-page');
  const nextBtn = document.getElementById('btn-next-page');
  const infoSpan = document.getElementById('pagination-info');

  // Tehdit paketlerinin index'lerini topla
  const alertPacketIndices = new Set(data.alerts ? data.alerts.map(a => a.packet_index).filter(idx => idx !== null) : []);

  // Hızlı Filtre Butonları Tıklama Dinleyicileri
  const filterButtons = document.querySelectorAll('#filter-buttons .btn-filter');
  filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      filterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      const filterType = btn.getAttribute('data-filter');
      if (searchInput) searchInput.value = ''; // Arama çubuğunu temizle
      
      if (filterType === 'all') {
        filteredPackets = data.packets ? [...data.packets] : [];
      } else if (filterType === 'alerts') {
        filteredPackets = data.packets ? data.packets.filter(pkt => alertPacketIndices.has(pkt.index)) : [];
      } else {
        filteredPackets = data.packets ? data.packets.filter(pkt => {
          let proto = 'other';
          const match = pkt.summary.match(/^\[\d+\]\s+([A-Za-z0-9\-]+)/);
          if (match) { proto = match[1].toLowerCase(); }
          
          if (pkt.summary.includes('| DNS')) proto = 'dns';
          else if (pkt.summary.includes('| HTTP')) proto = 'http';
          else if (pkt.summary.includes('| TLS')) proto = 'tls';
          
          return proto === filterType;
        }) : [];
      }
      
      currentPage = 1;
      renderTable();
    });
  });

  // Ağaç Genişlet / Kapat Butonları Dinleyicileri
  const btnExpandAll = document.getElementById('btn-expand-all-trees');
  if (btnExpandAll) {
    btnExpandAll.addEventListener('click', () => {
      document.querySelectorAll('.details-row').forEach(row => {
        row.style.display = 'table-row';
      });
      document.querySelectorAll('.tree-node').forEach(node => {
        node.classList.add('expanded');
      });
    });
  }

  const btnCollapseAll = document.getElementById('btn-collapse-all-trees');
  if (btnCollapseAll) {
    btnCollapseAll.addEventListener('click', () => {
      document.querySelectorAll('.tree-node').forEach(node => {
        node.classList.remove('expanded');
      });
      document.querySelectorAll('.details-row').forEach(row => {
        row.style.display = 'none';
      });
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      // Filtre grubunu "Tümü" yap
      filterButtons.forEach(b => {
        if (b.getAttribute('data-filter') === 'all') b.classList.add('active');
        else b.classList.remove('active');
      });

      if (q === '') {
        filteredPackets = data.packets ? [...data.packets] : [];
      } else {
        filteredPackets = data.packets.filter(pkt => 
          pkt.summary.toLowerCase().includes(q) || 
          pkt.index.toString() === q
        );
      }
      currentPage = 1;
      renderTable();
    });
  }

  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        renderTable();
      }
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      const maxPages = Math.ceil(filteredPackets.length / pageSize);
      if (currentPage < maxPages) {
        currentPage++;
        renderTable();
      }
    });
  }

  function renderTable() {
    if (!tableBody) return;
    tableBody.innerHTML = '';

    const total = filteredPackets.length;
    const maxPages = Math.ceil(total / pageSize) || 1;
    
    if (total === 0) {
      tableBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 30px;">Aradığınız kriterlere uygun paket bulunamadı.</td></tr>`;
      infoSpan.textContent = `Paketler gösteriliyor: 0 - 0 / 0`;
      prevBtn.disabled = true;
      nextBtn.disabled = true;
      return;
    }

    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const slice = filteredPackets.slice(startIdx, endIdx);

    slice.forEach(pkt => {
      let proto = 'other';
      const match = pkt.summary.match(/^\[\d+\]\s+([A-Za-z0-9\-]+)/);
      if (match) {
        proto = match[1].toLowerCase();
      }

      if (pkt.summary.includes('| DNS')) proto = 'dns';
      else if (pkt.summary.includes('| HTTP')) proto = 'http';
      else if (pkt.summary.includes('| TLS')) proto = 'tls';

      const parts = pkt.summary.split('|');
      const headerPart = parts[0].replace(/^\[\d+\]\s*/, '').trim();

      const mainRow = document.createElement('tr');
      mainRow.id = `packet-row-${pkt.index}`;
      mainRow.innerHTML = `
        <td class="packet-index-col">#${pkt.index}</td>
        <td class="packet-proto-col"><span class="proto-badge ${proto}">${proto}</span></td>
        <td style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 500;">${escapeHtml(headerPart)}</td>
      `;

      const detailRow = document.createElement('tr');
      detailRow.className = 'details-row';
      detailRow.style.display = 'none';
      detailRow.id = `packet-details-${pkt.index}`;
      
      const treeHTML = buildPacketTreeHTML(pkt);
      detailRow.innerHTML = `
        <td></td>
        <td colspan="2">
          ${treeHTML}
        </td>
      `;

      detailRow.querySelectorAll('.btn-tree-toggle').forEach(header => {
        header.addEventListener('click', (e) => {
          if (e.target.classList.contains('btn-info-circle')) return;
          const node = header.parentElement;
          node.classList.toggle('expanded');
        });
      });

      detailRow.querySelectorAll('.btn-info-circle').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          const infoKey = btn.getAttribute('data-info');
          showLayerExplanationModal(infoKey);
        });
      });

      mainRow.addEventListener('click', () => {
        const isHidden = detailRow.style.display === 'none';
        tableBody.querySelectorAll('.details-row').forEach(row => {
          row.style.display = 'none';
        });
        detailRow.style.display = isHidden ? 'table-row' : 'none';
        if (isHidden) {
          lucide.createIcons();
        }
      });

      tableBody.appendChild(mainRow);
      tableBody.appendChild(detailRow);
    });

    infoSpan.textContent = `Paketler gösteriliyor: ${startIdx + 1} - ${endIdx} / ${total}`;
    prevBtn.disabled = (currentPage === 1);
    nextBtn.disabled = (currentPage === maxPages);
  }

  renderTable();

  function focusOnPacket(index) {
    const foundIdx = filteredPackets.findIndex(pkt => pkt.index === index);
    if (foundIdx === -1) {
      if (searchInput) searchInput.value = '';
      filteredPackets = [...data.packets];
      return focusOnPacket(index);
    }

    currentPage = Math.floor(foundIdx / pageSize) + 1;
    renderTable();

    setTimeout(() => {
      const row = document.getElementById(`packet-row-${index}`);
      const details = document.getElementById(`packet-details-${index}`);
      if (row && details) {
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.style.backgroundColor = 'rgba(56, 139, 253, 0.15)';
        setTimeout(() => { row.style.backgroundColor = ''; }, 1500);
        details.style.display = 'table-row';
      }
    }, 100);
  }

  // 10. Protokol Rehberi Açma/Kapama Kontrolü
  const toggleGuideBtn = document.getElementById('btn-toggle-guide');
  const guideBox = document.getElementById('protocol-guide-box');
  if (toggleGuideBtn && guideBox) {
    // Varsayılan olarak açık başlasın
    guideBox.style.display = 'block';
    toggleGuideBtn.innerHTML = '<i data-lucide="book-open" style="width:12px;height:12px;margin-right:4px;"></i> Rehberi Kapat';

    toggleGuideBtn.addEventListener('click', () => {
      const isHidden = guideBox.style.display === 'none' || guideBox.style.display === '';
      guideBox.style.display = isHidden ? 'block' : 'none';
      toggleGuideBtn.innerHTML = isHidden 
        ? '<i data-lucide="book-open" style="width:12px;height:12px;margin-right:4px;"></i> Rehberi Kapat' 
        : '<i data-lucide="book-open" style="width:12px;height:12px;margin-right:4px;"></i> Rehber';
      lucide.createIcons();
    });
  }

  // 11. Kart Büyütme / Odak Modu (Maximize Card Focus Mode)
  const overlay = document.getElementById('fullscreen-overlay');
  const headerWrappers = document.querySelectorAll('.card-header-wrapper');

  function toggleMaximize(card, btn) {
    const isMaximized = card.classList.contains('maximized');
    
    // Herhangi bir kart zaten büyütülmüşse önce onu kapat
    document.querySelectorAll('.cockpit-card.maximized').forEach(c => {
      if (c !== card) {
        c.classList.remove('maximized');
        const otherBtn = c.querySelector('.btn-card-maximize');
        if (otherBtn) {
          otherBtn.innerHTML = '<i data-lucide="maximize-2" style="width:14px;height:14px;"></i>';
          otherBtn.title = 'Odak Modu';
        }
      }
    });

    if (isMaximized) {
      card.classList.remove('maximized');
      if (btn) {
        btn.innerHTML = '<i data-lucide="maximize-2" style="width:14px;height:14px;"></i>';
        btn.title = 'Odak Modu';
      }
      if (overlay) overlay.classList.remove('active');
    } else {
      card.classList.add('maximized');
      if (btn) {
        btn.innerHTML = '<i data-lucide="x" style="width:14px;height:14px;"></i>';
        btn.title = 'Odak Modunu Kapat';
      }
      if (overlay) overlay.classList.add('active');
      
      // vis.js ağ haritasını yeni boyutlara göre yeniden konumlandır ve sığdır
      if (card.id === 'card-topology' && network) {
        setTimeout(() => {
          network.redraw();
          network.fit({ animation: { duration: 300 } });
        }, 360);
      }
    }
    lucide.createIcons();
  }

  headerWrappers.forEach(wrapper => {
    wrapper.addEventListener('click', (e) => {
      // Eğer tıklama buton (maximize hariç), input veya link üzerindeyse odak modunu tetikleme
      if (e.target.closest('button') && !e.target.closest('.btn-card-maximize')) return;
      if (e.target.closest('input') || e.target.closest('a')) return;

      const card = wrapper.closest('.cockpit-card');
      const btn = wrapper.querySelector('.btn-card-maximize');
      if (card) toggleMaximize(card, btn);
    });
  });

  if (overlay) {
    overlay.addEventListener('click', () => {
      document.querySelectorAll('.cockpit-card.maximized').forEach(card => {
        toggleMaximize(card, card.querySelector('.btn-card-maximize'));
      });
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.cockpit-card.maximized').forEach(card => {
        toggleMaximize(card, card.querySelector('.btn-card-maximize'));
      });
    }
  });

  // --- Eğitim Amaçlı Protokol Rehber Modalı Entegrasyonu ---
  const protocolExplanations = {
    tcp: {
      title: "TCP (Transmission Control Protocol) Nedir?",
      text: "<strong>TCP</strong> (Geçiş Kontrol Protokolü), ağ üzerindeki cihazların güvenilir, hatasız ve sıralı bir şekilde haberleşmesini sağlayan bağlantı yönelimli bir taşıma protokolüdür. Gönderilen her paket için alıcıdan onay (ACK) bekler. Paketlerin sırasının bozulmamasını ve hedefe ulaştığını garanti eder. Web siteleri (HTTP/HTTPS), e-posta, dosya indirme (FTP) ve SSH gibi veri kaybının kabul edilemeyeceği senaryolarda kullanılır."
    },
    udp: {
      title: "UDP (User Datagram Protocol) Nedir?",
      text: "<strong>UDP</strong> (Kullanıcı Veri Bloğu Protokolü), paketlerin alıcıya ulaşıp ulaşmadığını veya sırasını kontrol etmeyen, bağlantısız ve hızlı bir taşıma protokolüdür. Onay mekanizması olmadığı için gecikme son derece düşüktür. Canlı yayınlar, sesli/görüntülü aramalar (VoIP), online oyunlar ve DNS sorguları gibi hızın veri kaybından daha kritik olduğu yerlerde kullanılır."
    },
    arp: {
      title: "ARP (Address Resolution Protocol) Nedir?",
      text: "<strong>ARP</strong> (Adres Çözümleme Protokolü), yerel ağdaki cihazların sanal IP adreslerini (örn: 192.168.1.10) fiziksel donanım adreslerine (MAC Adresi) eşlemek için kullanılan bir Layer 2 protokolüdür. Yerel ağda bir cihaz diğerine veri göndereceğinde ARP yayını yaparak 'Bu IP kime ait?' diye sorar ve gelen cevapla MAC adresini öğrenir."
    },
    dns: {
      title: "DNS (Domain Name System) Nedir?",
      text: "<strong>DNS</strong> (Alan Adı Sistemi), internetin telefon rehberidir. İnsanların okuyabileceği alan adlarını (örn: google.com) bilgisayarların anlayabileceği sayısal IP adreslerine (örn: 142.250.185.78) çevirir. DNS sorguları genellikle son derece hızlı olması amacıyla <strong>UDP 53</strong> portu üzerinden gerçekleştirilir."
    },
    tls: {
      title: "TLS (Transport Layer Security) Nedir?",
      text: "<strong>TLS</strong> (Taşıma Katmanı Güvenliği), iki cihaz arasındaki iletişimi şifreleyerek araya giren kişilerin (Man-in-the-Middle) veriyi okumasını veya değiştirmesini engelleyen bir güvenlik protokolüdür. Eski SSL protokolünün güncel ve güvenli halidir. Web sitelerinde HTTPS üzerinden (genellikle TCP 443 portu) güvenli alışveriş ve veri iletimi sağlamak için kullanılır."
    },
    http: {
      title: "HTTP (HyperText Transfer Protocol) Nedir?",
      text: "<strong>HTTP</strong> (Köprü Metni Aktarım Protokolü), web tarayıcıları ve sunucular arasında web sayfalarının, resimlerin ve verilerin aktarılması için kullanılan uygulama katmanı protokolüdür. Şifreli versiyonu <strong>HTTPS</strong>, TLS/SSL katmanı üzerinde çalışarak tüm veriyi şifreler."
    }
  };

  function showEduModal(info) {
    let modal = document.getElementById('security-education-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'security-education-modal';
      modal.style.position = 'fixed';
      modal.style.top = '0';
      modal.style.left = '0';
      modal.style.width = '100vw';
      modal.style.height = '100vh';
      modal.style.backgroundColor = 'rgba(2, 6, 10, 0.88)';
      modal.style.backdropFilter = 'blur(10px)';
      modal.style.zIndex = '9999';
      modal.style.display = 'flex';
      modal.style.justifyContent = 'center';
      modal.style.alignItems = 'center';
      modal.style.opacity = '0';
      modal.style.transition = 'opacity 0.25s cubic-bezier(0.16, 1, 0.3, 1)';
      
      modal.innerHTML = `
        <div class="card" style="width: 90%; max-width: 500px; padding: 24px; position: relative; margin: 0; border: 1px solid var(--cyber-primary); box-shadow: 0 0 35px rgba(0, 255, 102, 0.25); background: #030c17;">
          <h2 id="edu-modal-title" style="margin-bottom: 12px; font-size: 1.1rem; color: var(--cyber-primary); border-bottom: 1px solid rgba(0,255,102,0.15); padding-bottom: 10px; font-family: var(--font-mono); font-weight:700;"></h2>
          <p id="edu-modal-text" style="font-size: 0.82rem; line-height: 1.6; color: var(--text-muted); margin-bottom: 20px; font-family: var(--font-main);"></p>
          <button id="edu-modal-close" class="btn btn-success" style="padding: 8px 16px; font-size: 0.8rem; width: auto; display: block; margin-left: auto;">Anladım, Teşekkürler</button>
        </div>
      `;
      document.body.appendChild(modal);
    }
    
    document.getElementById('edu-modal-title').textContent = info.title;
    document.getElementById('edu-modal-text').innerHTML = info.text;
    
    modal.style.display = 'flex';
    setTimeout(() => { modal.style.opacity = '1'; }, 50);
    
    const closeBtn = document.getElementById('edu-modal-close');
    closeBtn.onclick = () => {
      modal.style.opacity = '0';
      setTimeout(() => { modal.style.display = 'none'; }, 250);
    };
  }

  // Event delegation to catch clicks on proto badges (term-proto, alert-badge, etc.)
  document.body.addEventListener('click', (e) => {
    const protoEl = e.target.closest('.term-proto, .alert-badge, .badge-proto, .protocol-guide-name');
    if (protoEl) {
      const txt = protoEl.textContent.trim().toLowerCase();
      const matchedKey = Object.keys(protocolExplanations).find(k => txt.includes(k));
      if (matchedKey) {
        e.preventDefault();
        e.stopPropagation();
        showEduModal(protocolExplanations[matchedKey]);
      }
    }
  });

  // İlk açılışta Lucide ikonlarını oluştur
  lucide.createIcons();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDashboard);
} else {
  initDashboard();
}
