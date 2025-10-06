import React, { useState } from 'react';
import {
  Typography,
  Card,
  CardContent,
  TextField,
  Button,
  Grid,
  Box,
  Alert,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem
} from '@mui/material';
import axios from 'axios';

function IssuerDemo() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  
  const [formData, setFormData] = useState({
    user_id: 'demo-user-1',
    document_type: 'DRIVER_LICENSE',
    given_name: 'Alice',
    family_name: 'Smith',
    birth_date: '1990-05-15',
    license_number: 'DL123456789',
    license_class: 'C'
  });

  const handleInputChange = (event) => {
    const { name, value } = event.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const issueMDL = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post('/api/issuer/credentials/mdl', {
        user_id: formData.user_id,
        license_number: formData.license_number,
        person_info: {
          given_name: formData.given_name,
          family_name: formData.family_name,
          birth_date: formData.birth_date,
          nationality: 'US'
        },
        driving_privileges: {
          license_class: formData.license_class
        }
      });

      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to issue mDL');
    } finally {
      setLoading(false);
    }
  };

  const issueMDoc = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post('/api/issuer/credentials/mdoc', {
        user_id: formData.user_id,
        document_type: formData.document_type,
        person_info: {
          given_name: formData.given_name,
          family_name: formData.family_name,
          birth_date: formData.birth_date,
          nationality: 'US'
        }
      });

      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to issue mDoc');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        Credential Issuer Demo
      </Typography>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Issue mDL (Mobile Driving License) and mDoc (Mobile Document) credentials
        using the OpenWallet Foundation Multipaz SDK.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Issue Credential
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="User ID"
                    name="user_id"
                    value={formData.user_id}
                    onChange={handleInputChange}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <FormControl fullWidth>
                    <InputLabel>Document Type</InputLabel>
                    <Select
                      name="document_type"
                      value={formData.document_type}
                      onChange={handleInputChange}
                      label="Document Type"
                    >
                      <MenuItem value="DRIVER_LICENSE">Driver License (mDL)</MenuItem>
                      <MenuItem value="ID_CARD">Identity Card</MenuItem>
                      <MenuItem value="PASSPORT">Passport</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                
                <Grid item xs={6}>
                  <TextField
                    fullWidth
                    label="Given Name"
                    name="given_name"
                    value={formData.given_name}
                    onChange={handleInputChange}
                  />
                </Grid>
                
                <Grid item xs={6}>
                  <TextField
                    fullWidth
                    label="Family Name"
                    name="family_name"
                    value={formData.family_name}
                    onChange={handleInputChange}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Birth Date"
                    name="birth_date"
                    type="date"
                    value={formData.birth_date}
                    onChange={handleInputChange}
                    InputLabelProps={{ shrink: true }}
                  />
                </Grid>
                
                {formData.document_type === 'DRIVER_LICENSE' && (
                  <>
                    <Grid item xs={6}>
                      <TextField
                        fullWidth
                        label="License Number"
                        name="license_number"
                        value={formData.license_number}
                        onChange={handleInputChange}
                      />
                    </Grid>
                    
                    <Grid item xs={6}>
                      <FormControl fullWidth>
                        <InputLabel>License Class</InputLabel>
                        <Select
                          name="license_class"
                          value={formData.license_class}
                          onChange={handleInputChange}
                          label="License Class"
                        >
                          <MenuItem value="A">Class A</MenuItem>
                          <MenuItem value="B">Class B</MenuItem>
                          <MenuItem value="C">Class C</MenuItem>
                          <MenuItem value="M">Motorcycle</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>
                  </>
                )}
                
                <Grid item xs={12}>
                  <Box sx={{ display: 'flex', gap: 2 }}>
                    {formData.document_type === 'DRIVER_LICENSE' ? (
                      <Button
                        variant="contained"
                        onClick={issueMDL}
                        disabled={loading}
                        startIcon={loading && <CircularProgress size={20} />}
                      >
                        Issue mDL
                      </Button>
                    ) : (
                      <Button
                        variant="contained"
                        onClick={issueMDoc}
                        disabled={loading}
                        startIcon={loading && <CircularProgress size={20} />}
                      >
                        Issue mDoc
                      </Button>
                    )}
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Result
              </Typography>
              
              {error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {error}
                </Alert>
              )}
              
              {result && (
                <Alert severity="success" sx={{ mb: 2 }}>
                  Credential issued successfully!
                  <Box component="pre" sx={{ mt: 1, fontSize: '0.75rem', overflow: 'auto' }}>
                    {JSON.stringify(result, null, 2)}
                  </Box>
                </Alert>
              )}
              
              {!result && !error && !loading && (
                <Typography color="text.secondary">
                  Fill out the form and click "Issue" to create a credential.
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default IssuerDemo;