import React, { useState } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  TextField,
  Box,
  Alert,
  Stepper,
  Step,
  StepLabel,
  CircularProgress,
  Chip
} from '@mui/material';
import {
  CardMembership as CardIcon,
  Person as PersonIcon,
  LocationOn as LocationIcon,
  CalendarToday as CalendarIcon
} from '@mui/icons-material';

const IssuerDemo = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [issuanceResult, setIssuanceResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    given_name: 'Jane',
    family_name: 'Doe',
    birth_date: '1990-01-01',
    document_number: 'DL123456789',
    issuing_country: 'XX',
    issuing_authority: 'Demo DMV',
    expiry_date: '2030-01-01'
  });

  const steps = ['Enter Information', 'Review Data', 'Issue Credential'];

  const handleInputChange = (field) => (event) => {
    setFormData({
      ...formData,
      [field]: event.target.value
    });
  };

  const handleNext = () => {
    if (activeStep === steps.length - 1) {
      issueCredential();
    } else {
      setActiveStep((prevActiveStep) => prevActiveStep + 1);
    }
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const issueCredential = async () => {
    setLoading(true);
    
    try {
      const response = await fetch('/api/issuer/issue', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          credential_type: 'mDL',
          subject_data: formData,
          issuer_id: 'demo_issuer'
        })
      });
      
      const result = await response.json();
      setIssuanceResult(result);
    } catch (error) {
      console.error('Issuance failed:', error);
      setIssuanceResult({
        success: false,
        error: 'Failed to issue credential'
      });
    } finally {
      setLoading(false);
    }
  };

  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Grid container spacing={3}>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Given Name"
                value={formData.given_name}
                onChange={handleInputChange('given_name')}
                InputProps={{
                  startAdornment: <PersonIcon sx={{ mr: 1, color: 'action.active' }} />
                }}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Family Name"
                value={formData.family_name}
                onChange={handleInputChange('family_name')}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Birth Date"
                type="date"
                value={formData.birth_date}
                onChange={handleInputChange('birth_date')}
                InputLabelProps={{ shrink: true }}
                InputProps={{
                  startAdornment: <CalendarIcon sx={{ mr: 1, color: 'action.active' }} />
                }}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Document Number"
                value={formData.document_number}
                onChange={handleInputChange('document_number')}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Issuing Country"
                value={formData.issuing_country}
                onChange={handleInputChange('issuing_country')}
                InputProps={{
                  startAdornment: <LocationIcon sx={{ mr: 1, color: 'action.active' }} />
                }}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Expiry Date"
                type="date"
                value={formData.expiry_date}
                onChange={handleInputChange('expiry_date')}
                InputLabelProps={{ shrink: true }}
              />
            </Grid>
          </Grid>
        );
      
      case 1:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Review Credential Data
            </Typography>
            <Grid container spacing={2}>
              {Object.entries(formData).map(([key, value]) => (
                <Grid item xs={12} sm={6} key={key}>
                  <Card variant="outlined">
                    <CardContent sx={{ py: 1 }}>
                      <Typography color="text.secondary" variant="caption">
                        {key.replace('_', ' ').toUpperCase()}
                      </Typography>
                      <Typography variant="body1">
                        {value}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        );
      
      case 2:
        return (
          <Box textAlign="center">
            {loading ? (
              <Box>
                <CircularProgress size={60} />
                <Typography variant="h6" sx={{ mt: 2 }}>
                  Issuing Credential...
                </Typography>
                <Typography color="text.secondary">
                  Creating mDL credential using OpenWallet Foundation SDK
                </Typography>
              </Box>
            ) : issuanceResult ? (
              <Box>
                {issuanceResult.success ? (
                  <Box>
                    <Alert severity="success" sx={{ mb: 2 }}>
                      Credential issued successfully!
                    </Alert>
                    <Typography variant="h6" gutterBottom>
                      Credential Details
                    </Typography>
                    <Chip 
                      label={`ID: ${issuanceResult.credential.id}`} 
                      color="primary" 
                      sx={{ m: 0.5 }}
                    />
                    <Chip 
                      label={`Type: ${issuanceResult.credential.type}`} 
                      color="secondary" 
                      sx={{ m: 0.5 }}
                    />
                    <Chip 
                      label={`Format: ${issuanceResult.credential.format}`} 
                      sx={{ m: 0.5 }}
                    />
                  </Box>
                ) : (
                  <Alert severity="error">
                    {issuanceResult.error || 'Failed to issue credential'}
                  </Alert>
                )}
              </Box>
            ) : null}
          </Box>
        );
      
      default:
        return 'Unknown step';
    }
  };

  return (
    <Container maxWidth="md">
      <Paper sx={{ p: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center">
          <CardIcon sx={{ fontSize: 48, mr: 2, verticalAlign: 'middle' }} />
          Credential Issuer Demo
        </Typography>
        
        <Typography variant="body1" color="text.secondary" paragraph align="center">
          Issue mobile driving license (mDL) credentials using the OpenWallet Foundation SDK.
          This demo simulates the credential issuance process for a mobile driving license.
        </Typography>

        <Box sx={{ mb: 4 }}>
          <Stepper activeStep={activeStep}>
            {steps.map((label) => (
              <Step key={label}>
                <StepLabel>{label}</StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>

        <Box sx={{ mb: 4 }}>
          {renderStepContent(activeStep)}
        </Box>

        <Box sx={{ display: 'flex', flexDirection: 'row', pt: 2 }}>
          <Button
            color="inherit"
            disabled={activeStep === 0}
            onClick={handleBack}
            sx={{ mr: 1 }}
          >
            Back
          </Button>
          <Box sx={{ flex: '1 1 auto' }} />
          <Button 
            onClick={handleNext}
            disabled={loading}
          >
            {activeStep === steps.length - 1 ? 'Issue Credential' : 'Next'}
          </Button>
        </Box>
      </Paper>
    </Container>
  );
};

export default IssuerDemo;