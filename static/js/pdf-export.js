// PDF export and A4 pagination utilities extracted from console.html

window.initPdfExport = function initPdfExport() {
  const btn = document.getElementById('btnPdfRel');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    try {
      const { jsPDF } = window.jspdf;
      const doc = new jsPDF("p", "mm", "a4");

      const pages = document.querySelectorAll('#a4-pages .a4-page');
      if (pages.length === 0) {
        alert('Nenhuma página encontrada para exportar. Gere um relatório primeiro.');
        return;
      }

      for (let index = 0; index < pages.length; index++) {
        const page = pages[index];
        if (index > 0) await new Promise(r => setTimeout(r, 100));
        try {
          const canvas = await html2canvas(page, {
            scale: 2,
            useCORS: true,
            allowTaint: true,
            backgroundColor: '#ffffff',
            logging: false,
            width: page.offsetWidth,
            height: page.offsetHeight,
            foreignObjectRendering: true,
            removeContainer: true
          });
          if (!canvas || canvas.width === 0 || canvas.height === 0) {
            throw new Error('Canvas inválido');
          }
          const imgData = canvas.toDataURL('image/png', 0.95);
          if (!imgData || imgData === 'data:,') throw new Error('Imagem inválida');
          const imgProps = doc.getImageProperties(imgData);
          if (!imgProps || !imgProps.width || !imgProps.height) throw new Error('Propriedades inválidas');
          const pdfWidth = doc.internal.pageSize.getWidth();
          const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
          if (index > 0) doc.addPage();
          doc.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
        } catch (err) {
          // fallback simples
          try {
            const canvas = await html2canvas(page, {
              scale: 1,
              useCORS: false,
              allowTaint: false,
              backgroundColor: '#ffffff',
              logging: false,
              ignoreElements: el => el.tagName === 'SCRIPT' || el.tagName === 'STYLE' || el.classList.contains('no-print')
            });
            if (canvas && canvas.width > 0 && canvas.height > 0) {
              const imgData = canvas.toDataURL('image/jpeg', 0.8);
              if (imgData && imgData !== 'data:,') {
                const imgProps = doc.getImageProperties(imgData);
                if (imgProps && imgProps.width && imgProps.height) {
                  const pdfWidth = doc.internal.pageSize.getWidth();
                  const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
                  if (index > 0) doc.addPage();
                  doc.addImage(imgData, 'JPEG', 0, 0, pdfWidth, pdfHeight);
                  continue;
                }
              }
            }
          } catch (_) {}
          if (index > 0) doc.addPage();
          doc.setFontSize(12);
          doc.text(`Erro ao processar página ${index + 1}`, 20, 50);
          doc.text('Esta página não pôde ser incluída no PDF.', 20, 70);
        }
      }
      doc.save('relatorio.pdf');
    } catch (error) {
      console.error('Erro geral na exportação PDF:', error);
      alert('Erro ao exportar PDF: ' + (error && error.message ? error.message : 'erro desconhecido'));
    }
  });
};

// Pagination utility
window.paginateHtmlToA4 = function paginateHtmlToA4(innerHTML){
  const temp = document.createElement('div');
  temp.style.position = 'absolute';
  temp.style.left = '-99999px';
  temp.style.top = '0';
  temp.style.width = '210mm';
  temp.style.padding = '18mm 16mm';
  temp.style.boxSizing = 'border-box';
  temp.innerHTML = innerHTML;
  document.body.appendChild(temp);

  const pageHeightPx = (() => {
    const probe = document.createElement('div');
    probe.className = 'a4-page';
    probe.style.visibility = 'hidden';
    document.body.appendChild(probe);
    const innerHeight = probe.clientHeight - parseFloat(getComputedStyle(probe).paddingTop) - parseFloat(getComputedStyle(probe).paddingBottom);
    document.body.removeChild(probe);
    return innerHeight;
  })();

  const pages = [];
  let current = document.createElement('div');
  current.style.height = pageHeightPx + 'px';
  current.style.boxSizing = 'border-box';
  current.style.overflow = 'hidden';

  const children = Array.from(temp.childNodes);
  const pushPage = () => {
    pages.push(current.innerHTML);
    current = document.createElement('div');
    current.style.height = pageHeightPx + 'px';
    current.style.boxSizing = 'border-box';
    current.style.overflow = 'hidden';
  };

  const willOverflow = () => {
    const wrap = document.createElement('div');
    wrap.style.position = 'absolute';
    wrap.style.left = '-99999px';
    wrap.style.top = '0';
    wrap.style.width = '210mm';
    wrap.style.padding = '18mm 16mm';
    wrap.style.boxSizing = 'border-box';
    wrap.innerHTML = current.innerHTML;
    document.body.appendChild(wrap);
    const h = wrap.scrollHeight;
    document.body.removeChild(wrap);
    return h > pageHeightPx;
  };

  for (const node of children){
    const holder = document.createElement('div');
    holder.appendChild(node.cloneNode(true));
    current.innerHTML += holder.innerHTML;
    if (willOverflow()){
      current.innerHTML = current.innerHTML.slice(0, current.innerHTML.length - holder.innerHTML.length);
      pushPage();
      current.innerHTML += holder.innerHTML;
    }
  }
  if (current.innerHTML.trim()) pushPage();

  document.body.removeChild(temp);
  return pages;
};

// Auto-init when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  try { window.initPdfExport(); } catch(e) { /* noop */ }
});


