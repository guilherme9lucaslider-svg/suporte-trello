/**
 * Utilitários para WhatsApp/telefone BR
 * - Normaliza, valida (10/11 dígitos), formata e constrói link wa.me
 */
window.WA = (function(){
  function onlyDigits(s){ return (s||'').replace(/\D+/g,''); }
  function isValidBR(digits){
    const d = onlyDigits(digits);
    return d.length === 10 || d.length === 11;
  }
  function toE164BR(digits){
    const d = onlyDigits(digits);
    return d.startsWith('55') ? '+'+d : '+55'+d;
  }
  function maskBR(input){
    let d = onlyDigits(input.value);
    if(d.length > 11) d = d.slice(0,11);
    if(d.length <= 10){
      // (DD) 1234-5678
      input.value = d.replace(/(\d{0,2})(\d{0,4})(\d{0,4}).*/, function(_,a,b,c){
        let out='';
        if(a) out += '('+a;
        if(a.length===2) out += ') ';
        if(b) out += b;
        if(c) out += '-'+c;
        return out;
      });
    } else {
      // (DD) 91234-5678
      input.value = d.replace(/(\d{0,2})(\d{0,5})(\d{0,4}).*/, function(_,a,b,c){
        let out='';
        if(a) out += '('+a;
        if(a.length===2) out += ') ';
        if(b) out += b;
        if(c) out += '-'+c;
        return out;
      });
    }
  }
  function digitsBR(input){ return onlyDigits(input.value); }
  function waLinkFromDigits(digits, text){
    const d = onlyDigits(digits);
    return `https://wa.me/55${d}?text=${encodeURIComponent(text||'Olá!')}`;
  }
  return { onlyDigits, isValidBR, toE164BR, maskBR, digitsBR: digitsBR = digitsBR = function(i){return onlyDigits(i.value)}, waLinkFromDigits };
})();
