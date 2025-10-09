import React, { useState, useEffect } from 'react';
import {
  Typography,
  Card,
  CardContent,
  Button,
  Grid,
  Box,
  Alert,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Paper
} from '@mui/material';
import QRCode from 'qrcode.react';
import axios from 'axios';

function VerifierDemo() {
  const [scenarios, setScenarios] = useState([]);
  const [selectedScenario, setSelectedScenario] = useState('');
  const [loading, setLoading] = useState(false);
  const [presentationRequest, setPresentationRequest] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadScenarios();
  }, []);

  const loadScenarios = async () => {
    try {
      const response = await axios.get('/api/verifier/demo/scenarios');
      setScenarios(response.data.scenarios);
      if (response.data.scenarios.length > 0) {
        setSelectedScenario(response.data.scenarios[0].id);
      }
    } catch (err) {
      setError('Failed to load demo scenarios');
    }
  };

  const createPresentationRequest = async () => {
    setLoading(true);
    setError(null);
    setPresentationRequest(null);
    setVerificationResult(null);

    try {
      const scenario = scenarios.find(s => s.id === selectedScenario);
      const response = await axios.post('/api/verifier/presentation/request', {
        verifier_id: 'demo_verifier',
        presentation_definition_id: scenario.presentation_definition_id
      });

      setPresentationRequest(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create presentation request');
    } finally {
      setLoading(false);
    }
  };

  const checkPresentationStatus = async () => {
    if (!presentationRequest) return;

    try {
      const response = await axios.get(`/api/verifier/presentation/status/${presentationRequest.request_id}`);

      if (response.data.status === 'VALID' || response.data.status === 'INVALID') {
        // Get verification result
        const resultResponse = await axios.get(`/api/verifier/presentation/result/${presentationRequest.request_id}`);
        setVerificationResult(resultResponse.data);
      }
    } catch (err) {
      console.error('Failed to check presentation status:', err);
    }
  };

  // Mock presentation submission for demo
  const simulatePresentation = async () => {
    if (!presentationRequest) return;

    setLoading(true);
    try {
      const response = await axios.post('/api/verifier/presentation/verify', {
        request_id: presentationRequest.request_id,
        presentation_submission: {
          id: 'demo_submission',
          definition_id: scenarios.find(s => s.id === selectedScenario)?.presentation_definition_id,
          descriptor_map: [
            {
              id: 'credential_1',
              format: 'mso_mdoc',
              path: '$'
            }
          ]
        },
        vp_token: 'mock_vp_token_for_demo'
      });

      setVerificationResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to verify presentation');
    } finally {
      setLoading(false);
    }
  };

  const selectedScenarioData = scenarios.find(s => s.id === selectedScenario);

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        Credential Verifier Demo
      </Typography>

      <Typography variant="body1" color="text.secondary" paragraph>
        Verify mDoc and mDL credentials using OpenID4VP and ISO 18013-5 protocols.
        Create presentation requests and verify credential presentations.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Verification Scenario
              </Typography>

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Select Scenario</InputLabel>
                <Select
                  value={selectedScenario}
                  onChange={(e) => setSelectedScenario(e.target.value)}
                  label="Select Scenario"
                >
                  {scenarios.map((scenario) => (
                    <MenuItem key={scenario.id} value={scenario.id}>
                      {scenario.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {selectedScenarioData && (
                <Paper sx={{ p: 2, mb: 2, bgcolor: 'grey.50' }}>
                  <Typography variant="subtitle2" gutterBottom>
                    {selectedScenarioData.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {selectedScenarioData.description}
                  </Typography>
                  <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                    Use Case: {selectedScenarioData.use_case}
                  </Typography>
                </Paper>
              )}

              <Button
                variant="contained"
                onClick={createPresentationRequest}
                disabled={loading || !selectedScenario}
                startIcon={loading && <CircularProgress size={20} />}
                fullWidth
              >
                Create Presentation Request
              </Button>

              {presentationRequest && (
                <Box sx={{ mt: 2 }}>
                  <Button
                    variant="outlined"
                    onClick={simulatePresentation}
                    disabled={loading}
                    fullWidth
                    sx={{ mt: 1 }}
                  >
                    Simulate Credential Presentation
                  </Button>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Presentation Request
              </Typography>

              {error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {error}
                </Alert>
              )}

              {presentationRequest && (
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    QR Code for Mobile Wallet
                  </Typography>
                  <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
                    <QRCode value={presentationRequest.presentation_uri} size={200} />
                  </Box>

                  <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                    <Typography variant="caption" component="div">
                      Request ID: {presentationRequest.request_id}
                    </Typography>
                    <Typography variant="caption" component="div">
                      Status: {presentationRequest.status}
                    </Typography>
                    <Typography variant="caption" component="div">
                      Expires: {new Date(presentationRequest.expires_at).toLocaleString()}
                    </Typography>
                  </Paper>
                </Box>
              )}

              {verificationResult && (
                <Box sx={{ mt: 2 }}>
                  <Alert
                    severity={verificationResult.status === 'VALID' ? 'success' : 'error'}
                    sx={{ mb: 2 }}
                  >
                    Verification Result: {verificationResult.status}
                    {verificationResult.trust_level && (
                      <Typography variant="caption" display="block">
                        Trust Level: {verificationResult.trust_level}
                      </Typography>
                    )}
                  </Alert>

                  {verificationResult.verified_claims && (
                    <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Verified Claims:
                      </Typography>
                      <Box component="pre" sx={{ fontSize: '0.75rem', overflow: 'auto' }}>
                        {JSON.stringify(verificationResult.verified_claims, null, 2)}
                      </Box>
                    </Paper>
                  )}

                  {verificationResult.errors && verificationResult.errors.length > 0 && (
                    <Paper sx={{ p: 2, bgcolor: 'red.50', mt: 2 }}>
                      <Typography variant="subtitle2" gutterBottom color="error">
                        Verification Errors:
                      </Typography>
                      {verificationResult.errors.map((error, index) => (
                        <Typography key={index} variant="body2" color="error">
                          • {error}
                        </Typography>
                      ))}
                    </Paper>
                  )}
                </Box>
              )}

              {!presentationRequest && !error && (
                <Typography color="text.secondary">
                  Select a scenario and create a presentation request to begin verification.
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default VerifierDemo;
