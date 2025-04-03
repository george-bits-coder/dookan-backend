import os
import sys
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from urllib.parse import urlparse
from flask_cors import CORS  # Import Flask-CORS
import re
from decimal import Decimal
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import timedelta
import uuid
import datetime

import psycopg2 
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
# Enable CORS for all routes
CORS(app)
# Add to your Flask app config
app.config['POSTGRES_CONFIG'] = {
    'host': 'localhost',
    'database': 'shopify_db',
    'user': 'admin',
    'password': 'securepassword',
    'port': 5432
}

def get_db_connection():
    return psycopg2.connect(
        cursor_factory=RealDictCursor,
        **app.config['POSTGRES_CONFIG']
    )
# Load environment variables
load_dotenv()



# Shopify GraphQL API endpoint and credentials
SHOPIFY_SHOP = os.getenv('SHOPIFY_SHOP', '').strip()
SHOPIFY_ACCESS_TOKEN = os.getenv('SHOPIFY_ACCESS_TOKEN', '').strip()
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expiration time
jwt = JWTManager(app)

# MongoDB Configuration

MONGO_URI = os.getenv('MONGO_URI')
DB_NAME = os.getenv('MONGO_DB_NAME', 'shopify_auth')

if not MONGO_URI:
    print("❌ Error: MONGO_URI environment variable is not set")
    sys.exit(1)

try:
    # Connect to MongoDB with a 5-second timeout
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    
    # Force a connection check
    client.server_info()
    
    # If we get here, connection was successful
    print("✅ Successfully connected to MongoDB Atlas!")
    print(f"🔗 Connection URI: {MONGO_URI}")
    print(f"📁 Database: {DB_NAME}")
    
    db = client[DB_NAME]
    users_collection = db['users']
    
except Exception as e:
    print(f"❌ MongoDB Connection Error: {e}")
    print("💡 Troubleshooting tips:")
    print("1. Check your MONGO_URI in .env file")
    print("2. Verify your Atlas cluster is running")
    print("3. Ensure your IP is whitelisted in Atlas Network Access")
    print("4. Check your database user credentials")
    sys.exit(1)


def log_product_event(event_type, user_id, product_id):
    """
    Updated event logger matching your actual table schema
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO identifier_events 
            (event_type, user_id, product_id, event_timestamp)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            RETURNING event_id
        """, (event_type, user_id, product_id))
        
        conn.commit()
        return cur.fetchone()['event_id']
    except Exception as e:
        app.logger.error(f"Failed to log event: {str(e)}")
        return None
    finally:
        if conn:
            conn.close()




def validate_shopify_credentials():
    if not SHOPIFY_SHOP:
        raise ValueError("SHOPIFY_SHOP environment variable is not set. Please set it in your .env file.")
    if not SHOPIFY_ACCESS_TOKEN:
        raise ValueError("SHOPIFY_ACCESS_TOKEN environment variable is not set. Please set it in your .env file.")
    
    # Remove any protocol (http://, https://) and trailing slashes
    parsed_shop = urlparse(SHOPIFY_SHOP)
    cleaned_shop = parsed_shop.netloc or parsed_shop.path
    
    # Check if cleaned shop looks like a valid Shopify store URL
    if not cleaned_shop.endswith('.myshopify.com'):
        raise ValueError(f"Invalid Shopify shop URL: {SHOPIFY_SHOP}. It should be in the format 'your-store.myshopify.com'")

# Call credential validation when the app starts
try:
    validate_shopify_credentials()
except ValueError as e:
    print(f"Shopify Credentials Error: {e}")
    sys.exit(1)

def get_clean_shopify_shop():
    # Remove protocol and any trailing slashes, keep only the shop domain
    parsed_shop = urlparse(SHOPIFY_SHOP)
    return (parsed_shop.netloc or parsed_shop.path).rstrip('/')

def create_shopify_graphql_request(query, variables=None):
    """
    Helper function to create a Shopify GraphQL request
    """
    # Clean the shop URL
    clean_shop = get_clean_shopify_shop()

    # Headers for the GraphQL request
    headers = {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
    }
    
    # Construct full Shopify GraphQL API endpoint
    shopify_graphql_url = f'https://{clean_shop}/admin/api/2024-01/graphql.json'
    
    try:
        # Send GraphQL query to Shopify
        response = requests.post(
            shopify_graphql_url, 
            json={'query': query, 'variables': variables or {}},
            headers=headers
        )
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Parse the response
        return response.json()
    
    except requests.HTTPError as e:
        status_code = e.response.status_code
        error_message = f"HTTP Error: {status_code}"
        
        # Try to get more detailed error info from response
        try:
            error_data = e.response.json()
            if 'errors' in error_data:
                error_message = f"Shopify API Error: {error_data['errors']}"
        except:
            pass
            
        return {
            'error': error_message,
            'status_code': status_code
        }
    except requests.RequestException as e:
        return {
            'error': 'Failed to connect to Shopify',
            'details': str(e)
        }
    except ValueError as e:
        return {
            'error': 'Invalid response from Shopify',
            'details': str(e)
        }

def validate_pagination_params(request):
    """Validate and extract pagination parameters"""
    errors = []
    
    # Validate 'first' parameter
    try:
        first = request.args.get('first', 50, type=int)
        if first <= 0:
            errors.append("Parameter 'first' must be a positive integer")
        if first > 250:  # Shopify's limit
            errors.append("Parameter 'first' cannot exceed 250")
    except ValueError:
        errors.append("Parameter 'first' must be a valid integer")
        first = 50  # Default
    
    # Validate 'after' cursor if provided
    after = request.args.get('after', None)
    if after is not None and not after.strip():
        errors.append("Parameter 'after' cannot be empty if provided")
    
    return first, after, errors

def validate_product_id(product_id):
    """Validate Shopify product ID format"""
    # Most Shopify GraphQL IDs follow the format 'gid://shopify/Product/1234567890'
    if not product_id:
        return False, "Product ID cannot be empty"
    
    # If it's already in the gid format
    if product_id.startswith('gid://shopify/Product/'):
        return True, None
    
    # If it's a numeric ID, we need to ensure it's valid
    if product_id.isdigit():
        return True, None
        
    return False, "Invalid product ID format"

def validate_create_product_data(data):
    """Validate product creation data"""
    errors = []
    
    # Check required fields
    required_fields = ['title', 'vendor', 'product_type', 'price']
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    
    # Validate price format
    if 'price' in data:
        try:
            price = float(data['price'])
            if price < 0:
                errors.append("Price cannot be negative")
        except (ValueError, TypeError):
            errors.append("Price must be a valid number")
    
    # Validate other fields
    if 'title' in data and (not data['title'] or len(data['title']) > 255):
        errors.append("Title must be between 1 and 255 characters")
    
    return errors

def validate_update_product_data(data):
    """Validate product update data"""
    errors = []
    
    # Ensure there's data to update
    if not data:
        errors.append("No update data provided")
        return errors
    
    # Validate price format if present
    if 'price' in data:
        try:
            price = float(data['price'])
            if price < 0:
                errors.append("Price cannot be negative")
        except (ValueError, TypeError):
            errors.append("Price must be a valid number")
    
    # Validate title length if present
    if 'title' in data and (not data['title'] or len(data['title']) > 255):
        errors.append("Title must be between 1 and 255 characters")
    
    return errors

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found", "details": str(e)}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed", "details": str(e)}), 405

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/hello', methods=['GET'])
def hello():
    return 'Shopify Product API is running!'

@app.route('/api/products', methods=['GET'])
@jwt_required()
def list_shopify_products():
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': current_user_id})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    try:
        # Get and validate query parameters for pagination and filtering
        first, after, validation_errors = validate_pagination_params(request)
        
        if validation_errors:
            return jsonify({"error": "Invalid request parameters", "details": validation_errors}), 400
        
        # Get and validate query parameter
        query = request.args.get('query', None)
        
        # Construct GraphQL query
        graphql_query = """
        query getProducts($first: Int!, $after: String, $query: String) {
            products(first: $first, after: $after, query: $query) {
                pageInfo {
                    hasNextPage
                    endCursor
                }
                edges {
                    node {
                        id
                        title
                        handle
                        productType
                        vendor
                        variants(first: 1) {
                            edges {
                                node {
                                    price
                                }
                            }
                        }
                        createdAt
                        updatedAt
                    }
                }
            }
        }
        """
        
        # Prepare variables for the GraphQL query
        variables = {
            "first": first,
            "after": after,
            "query": query
        }
        
        # Send GraphQL request
        response_data = create_shopify_graphql_request(graphql_query, variables)
        
        # Check for errors
        if 'error' in response_data:
            status_code = response_data.get('status_code', 500)
            return jsonify({"error": response_data['error'], "details": response_data.get('details', '')}), status_code
        
        if 'errors' in response_data:
            return jsonify({
                'error': 'GraphQL Query Error',
                'details': response_data['errors']
            }), 500
        
        # Check if products data exists
        if not response_data.get('data') or not response_data['data'].get('products'):
            return jsonify({
                'error': 'Invalid response from Shopify',
                'details': 'Products data not found in response'
            }), 500
        
        # Process and transform product data
        products_data = response_data['data']['products']
        products = []
        
        for edge in products_data['edges']:
            product = edge['node']
            
            # Handle case where variants might be empty
            price = "N/A"
            if product['variants']['edges']:
                price = product['variants']['edges'][0]['node']['price']
                
            products.append({
                'id': product['id'],
                'title': product['title'],
                'handle': product['handle'],
                'productType': product['productType'],
                'vendor': product['vendor'],
                'price': price,
                'createdAt': product['createdAt'],
                'updatedAt': product['updatedAt']
            })

        # Log product listing event
        log_product_event(
            event_type='LIST',
            user_id=current_user_id,
            product_id='ALL'
        )
        
        # Return products with pagination info
        return jsonify({
            'products': products,
            'pagination': {
                'hasNextPage': products_data['pageInfo']['hasNextPage'],
                'endCursor': products_data['pageInfo']['endCursor'],
                'count': len(products)
            }
        }), 200
    
    except Exception as e:
        return jsonify({
            'error': 'Failed to list products',
            'details': str(e)
        }), 500


@app.route('/api/products/<path:product_id>', methods=['GET'])
@jwt_required()
def get_shopify_product_by_id(product_id):
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': current_user_id})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    try:
        # Validate product ID
        is_valid, error = validate_product_id(product_id)
        if not is_valid:
            return jsonify({"error": "Invalid product ID", "details": error}), 400
        
        # Construct GraphQL query
        graphql_query = """
        query getProductById($id: ID!) {
            product(id: $id) {
                id
                title
                handle
                description
                productType
                vendor
                variants(first: 10) {
                    edges {
                        node {
                            id
                            price
                            compareAtPrice
                            availableForSale
                            selectedOptions {
                                name
                                value
                            }
                        }
                    }
                }
                images(first: 5) {
                    edges {
                        node {
                            originalSrc
                            altText
                        }
                    }
                }
                createdAt
                updatedAt
            }
        }
        """
        
        # Prepare variables for the GraphQL query
        # Format product_id to gid format if it's a numeric ID
        if product_id.isdigit():
            formatted_id = f"gid://shopify/Product/{product_id}"
        else:
            formatted_id = product_id
            
        variables = {
            "id": formatted_id
        }
        
        # Send GraphQL request
        response_data = create_shopify_graphql_request(graphql_query, variables)
        
        # Check for errors
        if 'error' in response_data:
            status_code = response_data.get('status_code', 500)
            return jsonify({"error": response_data['error'], "details": response_data.get('details', '')}), status_code
        
        if 'errors' in response_data:
            # Check if it's a "product not found" error
            for error in response_data.get('errors', []):
                if 'product not found' in error.get('message', '').lower():
                    return jsonify({
                        'error': 'Product not found',
                        'product_id': product_id
                    }), 404
            
            return jsonify({
                'error': 'GraphQL Query Error',
                'details': response_data['errors']
            }), 500
        
        # Check if data exists and product exists
        if not response_data.get('data') or not response_data['data'].get('product'):
            return jsonify({
                'error': 'Product not found',
                'product_id': product_id
            }), 404
        
        # Process product data
        product = response_data['data']['product']
        processed_product = {
            'id': product['id'],
            'title': product['title'],
            'handle': product['handle'],
            'description': product.get('description', ''),
            'productType': product['productType'],
            'vendor': product['vendor'],
            'createdAt': product['createdAt'],
            'updatedAt': product['updatedAt'],
            'variants': [
                {
                    'id': variant['node']['id'],
                    'price': variant['node']['price'],
                    'compareAtPrice': variant['node']['compareAtPrice'],
                    'availableForSale': variant['node']['availableForSale'],
                    'selectedOptions': variant['node']['selectedOptions']
                } for variant in product['variants']['edges']
            ],
            'images': [
                {
                    'originalSrc': image['node']['originalSrc'],
                    'altText': image['node']['altText']
                } for image in product['images']['edges']
            ]
        }

        # Log successful product retrieval
        log_product_event(
            event_type='VIEW',
            user_id=current_user_id,
            product_id=product_id
        )
        
        return jsonify(processed_product), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to retrieve product',
            'details': str(e)
        }), 500

@app.route('/api/products', methods=['POST'])
@jwt_required()
def create_shopify_product():
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': current_user_id})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    try:
        # Verify content type is JSON
        if not request.is_json:
            return jsonify({
                'error': 'Invalid Content-Type',
                'details': 'Request must be application/json'
            }), 415
        
        # Get product details from the request JSON
        product_data = request.json
        
        # Validate required fields and data formats
        validation_errors = validate_create_product_data(product_data)
        if validation_errors:
            return jsonify({
                'error': 'Invalid product data',
                'details': validation_errors
            }), 400
        
        # Construct GraphQL mutation
        mutation = """
        mutation productCreate($input: ProductInput!) {
            productCreate(input: $input) {
                product {
                    id
                    title
                    handle
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """
        
        # Prepare variables for the GraphQL mutation
        variables = {
            "input": {
                "title": product_data['title'],
                "bodyHtml": product_data.get('body_html', ''),
                "vendor": product_data['vendor'],
                "productType": product_data['product_type'],
                "variants": [{
                    "price": str(product_data['price'])
                }]
            }
        }
        
        # Add tags if provided
        if 'tags' in product_data:
            variables["input"]["tags"] = product_data['tags']
        
        # Send GraphQL request
        response_data = create_shopify_graphql_request(mutation, variables)
        
        # Check for errors
        if 'error' in response_data:
            status_code = response_data.get('status_code', 500)
            return jsonify({"error": response_data['error'], "details": response_data.get('details', '')}), status_code
        
        if 'errors' in response_data:
            return jsonify({
                'error': 'GraphQL Query Error',
                'details': response_data['errors']
            }), 500
        
        # Check if data exists
        if not response_data.get('data') or not response_data['data'].get('productCreate'):
            return jsonify({
                'error': 'Invalid response from Shopify',
                'details': 'Product creation data not found in response'
            }), 500
        
        # Check for user errors in product creation
        product_create_data = response_data['data']['productCreate']
        if product_create_data['userErrors'] and len(product_create_data['userErrors']) > 0:
            return jsonify({
                'error': 'Product Creation Failed',
                'user_errors': product_create_data['userErrors']
            }), 400
        
        # Check if product was created
        if not product_create_data.get('product'):
            return jsonify({
                'error': 'Product Creation Failed',
                'details': 'No product data returned from Shopify'
            }), 500
        
        # Extract product ID from Shopify response
        product_id = product_create_data['product']['id'].split('/')[-1]
        
        # Log successful creation
        log_product_event(
            event_type='CREATE',
            user_id=current_user_id,
            product_id=product_id
        )
        
        # Return successful product creation response
        return jsonify({
            'message': 'Product created successfully',
            'product': {
                'id': product_create_data['product']['id'],
                'title': product_create_data['product']['title'],
                'handle': product_create_data['product']['handle']
            }
        }), 201
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to create product',
            'details': str(e)
        }), 500



@app.route('/api/products/<path:product_id>', methods=['PUT'])
@jwt_required()
def update_shopify_product(product_id):
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': current_user_id})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        # Remove any whitespace and validate product ID exists
        product_id = product_id.strip()
        if not product_id:
            return jsonify({"error": "Product ID cannot be empty"}), 400

        # Verify content type
        if not request.is_json:
            return jsonify({
                'error': 'Invalid Content-Type',
                'details': 'Request must be application/json'
            }), 415
        
        # Get and validate update data
        product_data = request.json
        validation_errors = validate_update_product_data(product_data)
        if validation_errors:
            return jsonify({
                'error': 'Invalid update data',
                'details': validation_errors
            }), 400

        # Format product ID for Shopify - use as-is if it looks like a GraphQL ID,
        # otherwise assume it's a numeric ID or handle
        if product_id.startswith('gid://'):
            formatted_id = product_id
        else:
            formatted_id = f"gid://shopify/Product/{product_id}"

        # Prepare update input for Shopify
        update_input = {"id": formatted_id}
        
        # Field mappings from request to Shopify fields
        field_mappings = {
            'title': 'title',
            'body_html': 'bodyHtml',
            'description': 'bodyHtml',
            'vendor': 'vendor',
            'product_type': 'productType',
            'tags': 'tags'
        }
        
        # Add mapped fields to update input
        for request_field, shopify_field in field_mappings.items():
            if request_field in product_data:
                update_input[shopify_field] = product_data[request_field]
        
        # Handle price updates
        if 'price' in product_data:
            if 'variants' not in update_input:
                update_input['variants'] = [{}]
            update_input['variants'][0]['price'] = str(product_data['price'])
        
        # Handle inventory updates if provided
        if 'inventory_quantity' in product_data:
            if 'variants' not in update_input:
                update_input['variants'] = [{}]
            update_input['variants'][0]['inventoryQuantities'] = [{
                "availableQuantity": int(product_data['inventory_quantity']),
                "locationId": "gid://shopify/Location/1"  # Default location
            }]

        # Shopify GraphQL mutation
        mutation = """
        mutation productUpdate($input: ProductInput!) {
            productUpdate(input: $input) {
                product {
                    id
                    title
                    handle
                    variants(first: 1) {
                        edges {
                            node {
                                price
                                inventoryQuantity
                            }
                        }
                    }
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """
        
        # Execute Shopify update
        response_data = create_shopify_graphql_request(mutation, {"input": update_input})
        
        # Error handling
        if 'error' in response_data:
            return jsonify({
                "error": "Shopify API connection error",
                "details": response_data['error'],
                "shopify_id_used": formatted_id
            }), response_data.get('status_code', 500)
        
        if 'errors' in response_data:
            for error in response_data.get('errors', []):
                if 'product not found' in error.get('message', '').lower():
                    return jsonify({
                        'error': 'Product not found in Shopify',
                        'product_id': product_id,
                        'shopify_id_used': formatted_id
                    }), 404
            return jsonify({
                'error': 'GraphQL operation failed',
                'details': response_data['errors'],
                'shopify_id_used': formatted_id
            }), 500
        
        if not response_data.get('data') or not response_data['data'].get('productUpdate'):
            return jsonify({
                'error': 'Invalid response from Shopify',
                'details': 'Product update data not found in response',
                'shopify_id_used': formatted_id
            }), 500
        
        product_update_data = response_data['data']['productUpdate']
        
        # Check for Shopify user errors
        if product_update_data['userErrors']:
            return jsonify({
                'error': 'Product update rejected by Shopify',
                'user_errors': product_update_data['userErrors'],
                'shopify_id_used': formatted_id
            }), 400
        
        if not product_update_data.get('product'):
            return jsonify({
                'error': 'Product update failed',
                'details': 'No product data returned from Shopify',
                'shopify_id_used': formatted_id
            }), 500
        
        # Extract updated product data
        updated_product = product_update_data['product']
        response_product = {
            'id': updated_product['id'],
            'title': updated_product['title'],
            'handle': updated_product['handle']
        }
        
        # Include price and inventory if updated
        if updated_product.get('variants') and updated_product['variants']['edges']:
            variant = updated_product['variants']['edges'][0]['node']
            response_product['price'] = variant['price']
            if 'inventoryQuantity' in variant:
                response_product['inventory_quantity'] = variant['inventoryQuantity']
        
        # Log successful update
        log_product_event(
            event_type='UPDATE',
            user_id=current_user_id,
            product_id=product_id
        )
        
        return jsonify({
            'message': 'Product updated successfully',
            'product': response_product,
            'original_id': product_id,
            'shopify_id_used': formatted_id
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Unexpected error during product update',
            'details': str(e)
        }), 500

@app.route('/api/products/<path:product_id>', methods=['DELETE'])
@jwt_required()
def delete_shopify_product(product_id):
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': current_user_id})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        # Validate product ID
        is_valid, error = validate_product_id(product_id)
        if not is_valid:
            return jsonify({"error": "Invalid product ID", "details": error}), 400
        
        # Format product_id for Shopify
        formatted_id = f"gid://shopify/Product/{product_id}" if product_id.isdigit() else product_id
        
        # Validate the final ID format
        if not formatted_id.startswith('gid://shopify/Product/'):
            return jsonify({
                "error": "Invalid product ID format",
                "details": "Must be numeric ID or gid://shopify/Product/ format"
            }), 400

        # Shopify GraphQL mutation
        mutation = """
        mutation productDelete($input: ProductDeleteInput!) {
            productDelete(input: $input) {
                deletedProductId
                userErrors {
                    field
                    message
                }
            }
        }
        """
        
        variables = {"input": {"id": formatted_id}}
        response_data = create_shopify_graphql_request(mutation, variables)
        
        # Error handling
        if 'error' in response_data:
            return jsonify({
                "error": "Failed to connect to Shopify",
                "details": response_data['error']
            }), response_data.get('status_code', 500)
        
        if 'errors' in response_data:
            for error in response_data.get('errors', []):
                if 'product not found' in error.get('message', '').lower():
                    return jsonify({
                        'error': 'Product not found in Shopify',
                        'product_id': product_id
                    }), 404
            return jsonify({
                'error': 'GraphQL operation failed',
                'details': response_data['errors']
            }), 500
        
        if not response_data.get('data') or not response_data['data'].get('productDelete'):
            return jsonify({
                'error': 'Invalid response from Shopify',
                'details': 'Product deletion data not found in response'
            }), 500
        
        product_delete_data = response_data['data']['productDelete']
        if product_delete_data['userErrors']:
            return jsonify({
                'error': 'Product deletion rejected by Shopify',
                'user_errors': product_delete_data['userErrors']
            }), 400
        
        # Log successful deletion
        log_product_event(
            event_type='DELETE',
            user_id=current_user_id,
            product_id=product_id
        )
        
        return jsonify({
            'message': 'Product deleted successfully',
            'deleted_product_id': product_delete_data['deletedProductId']
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Unexpected error occurred',
            'details': str(e)
        }), 500

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        # Verify content type is JSON
        if not request.is_json:
            return jsonify({
                'error': 'Invalid Content-Type',
                'details': 'Request must be application/json'
            }), 415

        # Get user data from request
        data = request.json
        required_fields = ['email', 'password', 'name']
        
        # Validate required fields
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'error': 'Missing required field',
                    'details': f'{field} is required'
                }), 400

        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
            return jsonify({
                'error': 'Invalid email format'
            }), 400

        # Check if user already exists
        if users_collection.find_one({'email': data['email']}):
            return jsonify({
                'error': 'User already exists',
                'details': 'A user with this email already exists'
            }), 409

        # Hash password
        hashed_password = generate_password_hash(data['password'])

        # Create user document
        user = {
            '_id': str(uuid.uuid4()),
            'name': data['name'],
            'email': data['email'],
            'password': hashed_password,
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow()
        }

        # Insert user into MongoDB
        users_collection.insert_one(user)

        # Create JWT token
        access_token = create_access_token(identity=user['_id'])

        # Return success response with token
        return jsonify({
            'message': 'User created successfully',
            'access_token': access_token,
            'user': {
                'id': user['_id'],
                'name': user['name'],
                'email': user['email']
            }
        }), 201

    except Exception as e:
        return jsonify({
            'error': 'Failed to create user',
            'details': str(e)
        }), 500

@app.route('/api/auth/signin', methods=['POST'])
def signin():
    try:
        # Verify content type is JSON
        if not request.is_json:
            return jsonify({
                'error': 'Invalid Content-Type',
                'details': 'Request must be application/json'
            }), 415

        # Get credentials from request
        data = request.json
        required_fields = ['email', 'password']
        
        # Validate required fields
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'error': 'Missing required field',
                    'details': f'{field} is required'
                }), 400

        # Find user by email
        user = users_collection.find_one({'email': data['email']})
        if not user:
            return jsonify({
                'error': 'Invalid credentials',
                'details': 'User not found'
            }), 401

        # Verify password
        if not check_password_hash(user['password'], data['password']):
            return jsonify({
                'error': 'Invalid credentials',
                'details': 'Incorrect password'
            }), 401

        # Create JWT token
        access_token = create_access_token(identity=user['_id'])

        # Return success response with token
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user['_id'],
                'name': user['name'],
                'email': user['email']
            }
        }), 200

    except Exception as e:
        return jsonify({
            'error': 'Failed to authenticate user',
            'details': str(e)
        }), 500


from dateutil import parser
@app.route('/api/events', methods=['GET'])
def get_all_events():
    conn = None
    try:
        # Get query parameters
        event_type = request.args.get('event_type')
        user_id = request.args.get('user_id')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Base query
        query = """
            SELECT 
                event_id,
                event_type,
                user_id,
                product_id,
                event_timestamp AT TIME ZONE 'UTC' AS timestamp
            FROM identifier_events
            WHERE 1=1
        """
        
        # Add filters based on query parameters
        params = []
        
        if event_type:
            query += " AND event_type = %s"
            params.append(event_type)
            
        if user_id:
            query += " AND user_id = %s"
            params.append(user_id)
            
        if start_time:
            try:
                start_dt = parser.isoparse(start_time)
                query += " AND event_timestamp >= %s"
                params.append(start_dt)
            except ValueError:
                return jsonify({'error': 'Invalid start_time format. Use ISO format.'}), 400
                
        if end_time:
            try:
                end_dt = parser.isoparse(end_time)
                query += " AND event_timestamp <= %s"
                params.append(end_dt)
            except ValueError:
                return jsonify({'error': 'Invalid end_time format. Use ISO format.'}), 400
        
        # Add sorting
        query += " ORDER BY event_timestamp DESC"
        
        # Execute the query with parameters
        cur.execute(query, params)
        
        # Convert results to JSON format
        events = []
        for row in cur.fetchall():
            event = {
                'event_id': row['event_id'],
                'event_type': row['event_type'],
                'user_id': row['user_id'],
                'product_id': row['product_id'],
                'timestamp': row['timestamp'].isoformat() if row['timestamp'] else None
            }
            events.append(event)
        
        return jsonify({
            'count': len(events),
            'events': events
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to fetch events',
            'details': str(e)
        }), 500
    finally:
        if conn:
            conn.close()



# @app.route('/api/events', methods=['GET'])
# def get_all_events():
#     conn = None
#     try:
#         conn = get_db_connection()
#         cur = conn.cursor()
        
#         # Execute query and get all rows directly
#         cur.execute("""
#             SELECT 
#                 event_id,
#                 event_type,
#                 user_id,
#                 product_id,
#                 event_timestamp AT TIME ZONE 'UTC' AS timestamp
#             FROM identifier_events
#             ORDER BY event_timestamp DESC
#         """)
        
#         # Get all results as list of tuples
#         rows = cur.fetchall()

        
#         # Convert to list of dictionaries
#         # results = []
#         # for row in rows:
#         #     results.append({
#         #         "event_id": row[0],
#         #         "event_type": row[1],
#         #         "user_id": row[2],
#         #         "product_id": row[3],
#         #         "timestamp": row[4].isoformat() if row[4] else None
#         #     })

# https://images.pexels.com/photos/1666067/pexels-photo-1666067.jpeg?auto=compress&cs=tinysrgb&w=600
#         print("Query results:", rows) 
#         return jsonify("hi")
        
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#     finally:
#         if conn:
#             conn.close()




# Example of a protected route
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': current_user_id})
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    return jsonify({
        'message': 'This is a protected route',
        'user': {
            'id': user['_id'],
            'name': user['name'],
            'email': user['email']
        }
    }), 200


    
if __name__ == '__main__':
    app.run(debug=True)
