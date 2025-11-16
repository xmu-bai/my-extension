    // 从URL参数获取目标URL
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url') || '未知网站';
    
    // 显示URL
    document.getElementById('urlDisplay').textContent = decodeURIComponent(targetUrl);
    
    // 返回按钮
    document.getElementById('backBtn').addEventListener('click', () => {
      window.history.back();
    });
    
    // 继续访问按钮（警告）
    document.getElementById('continueBtn').addEventListener('click', () => {
      if (confirm('您确定要继续访问这个危险的网站吗？\n\n强烈建议不要继续！')) {
        window.location.href = targetUrl;
      }
    });