document.addEventListener('DOMContentLoaded', function() {
    // Get references to DOM elements
    const featuredProductsDiv = document.getElementById('featured-list');
    const allProductsDiv = document.getElementById('all-products');
    const cartItemsDiv = document.getElementById('cart-items');
    const totalPriceSpan = document.getElementById('total-price');
    const cartCountSpans = document.querySelectorAll('#cart-count, #cart-count-products, #cart-count-cart');
    const checkoutBtn = document.getElementById('checkout-btn');

    // Initialize cart from localStorage or an empty array
    let cart = JSON.parse(localStorage.getItem('cart')) || [];

    // Function to update cart count in all relevant spans
    function updateCartCount() {
        cartCountSpans.forEach(span => {
            span.textContent = cart.length;
        });
    }

    // Function to display products in a given container
    function displayProducts(products, container) {
        container.innerHTML = ''; // Clear the container
        products.forEach(product => {
            const productDiv = document.createElement('div');
            productDiv.classList.add('product-item');
            productDiv.innerHTML = `
                <img src="<span class="math-inline">\{product\.image\}" alt\="</span>{product.name}">
                <h3><span class="math-inline">\{product\.name\}</h3\>