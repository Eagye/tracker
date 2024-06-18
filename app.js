document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const role = document.getElementById('register-role').value;
  
    const response = await fetch('/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password, role }),
    });
  
    if (response.ok) {
      alert('User registered successfully');
    } else {
      alert('Registration failed');
    }
  });
  
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
  
    const response = await fetch('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });
  
    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('token', data.token);
      alert('Login successful');
    } else {
      alert('Login failed');
    }
  });
  
  document.getElementById('product-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const tagId = document.getElementById('product-tagId').value;
    const serialNumber = document.getElementById('product-serialNumber').value;
    const procurementDate = document.getElementById('product-procurementDate').value;
  
    const token = localStorage.getItem('token');
    const response = await fetch('/products', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token,
      },
      body: JSON.stringify({ tagId, serialNumber, procurementDate }),
    });
  
    if (response.ok) {
      alert('Product added successfully');
      loadProducts();
    } else {
      alert('Failed to add product');
    }
  });
  
  async function loadProducts() {
    const token = localStorage.getItem('token');
    const response = await fetch('/products', {
      headers: {
        'Authorization': token,
      },
    });
    const products = await response.json();
    const productList = document.getElementById('products');
    productList.innerHTML = '';
    products.forEach(product => {
      const li = document.createElement('li');
      li.textContent = `Tag ID: ${product.tagId}, Serial Number: ${product.serialNumber}, Procurement Date: ${new Date(product.procurementDate).toLocaleDateString()}`;
      productList.appendChild(li);
    });
  }
  
  document.addEventListener('DOMContentLoaded', loadProducts);