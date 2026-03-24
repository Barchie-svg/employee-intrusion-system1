
function togglePwd(fieldId, icon) {
  const field = document.getElementById(fieldId);
  if (field.type === 'password') {
    field.type = 'text';
    icon.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
  } else {
    field.type = 'password';
    icon.innerHTML = '<i class="fa-solid fa-eye"></i>';
  }
}
