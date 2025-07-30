const axios = require('axios');

const BASE_URL = 'http://localhost:3000/api';

// Test CSRF protection
const testCSRFProtection = async () => {
  console.log('🛡️ Testing CSRF Protection...\n');
  
  try {
    // Step 1: Get CSRF token
    console.log('📝 Step 1: Getting CSRF token...');
    const tokenResponse = await axios.get(`${BASE_URL}/csrf/token`, {
      headers: {
        'Content-Type': 'application/json'
      },
      withCredentials: true
    });
    
    console.log('✅ CSRF Token Response Status:', tokenResponse.status);
    console.log('✅ CSRF Token Response:', tokenResponse.data);
    
    if (tokenResponse.data.status === 'success') {
      const csrfToken = tokenResponse.data.data.token;
      console.log('✅ CSRF Token received:', csrfToken.substring(0, 8) + '...');
      
      // Step 2: Test sensitive operation WITH CSRF token (should succeed)
      console.log('\n📝 Step 2: Testing sensitive operation WITH CSRF token...');
      try {
        const protectedResponse = await axios.post(`${BASE_URL}/csrf/validate`, {
          token: csrfToken
        }, {
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
          },
          withCredentials: true
        });
        
        console.log('✅ Protected Request Response Status:', protectedResponse.status);
        console.log('✅ Protected Request Response:', protectedResponse.data);
        
      } catch (error) {
        console.log('❌ Protected request failed:', error.response?.data);
      }
      
      // Step 3: Test sensitive operation WITHOUT CSRF token (should fail)
      console.log('\n📝 Step 3: Testing sensitive operation WITHOUT CSRF token...');
      try {
        const unprotectedResponse = await axios.post(`${BASE_URL}/csrf/validate`, {
          token: csrfToken
        }, {
          headers: {
            'Content-Type': 'application/json'
            // No X-CSRF-Token header
          },
          withCredentials: true
        });
        
        console.log('❌ Unprotected request should have failed but succeeded:', unprotectedResponse.status);
        
      } catch (error) {
        if (error.response && error.response.status === 403) {
          console.log('✅ Unprotected request correctly returned 403 (forbidden)');
          console.log('✅ CSRF protection is working!');
        } else {
          console.log('❌ Unexpected error for unprotected request:', error.response?.status);
        }
      }
      
      // Step 4: Test with invalid CSRF token (should fail)
      console.log('\n📝 Step 4: Testing with invalid CSRF token...');
      try {
        const invalidTokenResponse = await axios.post(`${BASE_URL}/csrf/validate`, {
          token: 'invalid-token'
        }, {
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': 'invalid-token'
          },
          withCredentials: true
        });
        
        console.log('❌ Invalid token request should have failed but succeeded:', invalidTokenResponse.status);
        
      } catch (error) {
        if (error.response && error.response.status === 403) {
          console.log('✅ Invalid token request correctly returned 403 (forbidden)');
          console.log('✅ CSRF token validation is working!');
        } else {
          console.log('❌ Unexpected error for invalid token request:', error.response?.status);
        }
      }
      
      // Step 5: Test CSRF token refresh
      console.log('\n📝 Step 5: Testing CSRF token refresh...');
      try {
        const refreshResponse = await axios.post(`${BASE_URL}/csrf/refresh`, {}, {
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
          },
          withCredentials: true
        });
        
        console.log('✅ Token Refresh Response Status:', refreshResponse.status);
        console.log('✅ Token Refresh Response:', refreshResponse.data);
        
        if (refreshResponse.data.status === 'success') {
          const newToken = refreshResponse.data.data.token;
          console.log('✅ New CSRF Token received:', newToken.substring(0, 8) + '...');
        }
        
      } catch (error) {
        console.log('❌ Token refresh failed:', error.response?.data);
      }
      
    } else {
      console.log('❌ Failed to get CSRF token:', tokenResponse.data.message);
    }
    
  } catch (error) {
    console.log('❌ Error during CSRF test:');
    if (error.response) {
      console.log('Error Status:', error.response.status);
      console.log('Error Data:', error.response.data);
    } else {
      console.log('Network Error:', error.message);
    }
  }
};

// Test CSRF with user authentication
const testCSRFWithAuth = async () => {
  console.log('\n🔐 Testing CSRF with User Authentication...\n');
  
  try {
    // Step 1: Login to get authentication
    console.log('📝 Step 1: Logging in...');
    const loginResponse = await axios.post(`${BASE_URL}/user/simple-login`, {
      email: 'test@example.com',
      password: 'TestPassword123!'
    }, {
      headers: {
        'Content-Type': 'application/json'
      },
      withCredentials: true
    });
    
    if (loginResponse.data.status === 'success') {
      console.log('✅ Login successful');
      
      // Step 2: Get CSRF token while authenticated
      console.log('\n📝 Step 2: Getting CSRF token while authenticated...');
      const tokenResponse = await axios.get(`${BASE_URL}/csrf/token`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${loginResponse.data.data.token}`
        },
        withCredentials: true
      });
      
      if (tokenResponse.data.status === 'success') {
        const csrfToken = tokenResponse.data.data.token;
        console.log('✅ Authenticated CSRF Token received:', csrfToken.substring(0, 8) + '...');
        
        // Step 3: Test protected operation with both auth and CSRF
        console.log('\n📝 Step 3: Testing protected operation with auth and CSRF...');
        try {
          const protectedResponse = await axios.post(`${BASE_URL}/csrf/refresh`, {}, {
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${loginResponse.data.data.token}`,
              'X-CSRF-Token': csrfToken
            },
            withCredentials: true
          });
          
          console.log('✅ Protected Operation Response Status:', protectedResponse.status);
          console.log('✅ Protected Operation Response:', protectedResponse.data);
          
        } catch (error) {
          console.log('❌ Protected operation failed:', error.response?.data);
        }
      }
    } else {
      console.log('❌ Login failed:', loginResponse.data.message);
    }
    
  } catch (error) {
    console.log('❌ Error during authenticated CSRF test:');
    if (error.response) {
      console.log('Error Status:', error.response.status);
      console.log('Error Data:', error.response.data);
    } else {
      console.log('Network Error:', error.message);
    }
  }
};

// Main test function
const runTests = async () => {
  console.log('🚀 Starting CSRF Protection Tests...\n');
  
  await testCSRFProtection();
  await testCSRFWithAuth();
  
  console.log('\n📋 Summary:');
  console.log('✅ CSRF tokens should be generated and sent to frontend');
  console.log('✅ Sensitive operations should require valid CSRF tokens');
  console.log('✅ Requests without CSRF tokens should be rejected');
  console.log('✅ Invalid CSRF tokens should be rejected');
  console.log('✅ CSRF tokens should work with authentication');
};

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { testCSRFProtection, testCSRFWithAuth }; 