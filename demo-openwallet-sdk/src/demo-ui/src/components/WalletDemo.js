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
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Paper,
  TextField
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  QrCodeScanner as QrIcon
} from '@mui/icons-material';
import axios from 'axios';

function WalletDemo() {
  const [credentials, setCredentials] = useState([]);
  const [walletStatus, setWalletStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedUserId, setSelectedUserId] = useState('demo-user-1');
  const [selectedCredential, setSelectedCredential] = useState(null);

  useEffect(() => {
    loadWalletData();
  }, [selectedUserId]);

  const loadWalletData = async () => {
    setLoading(true);
    try {
      // Load wallet status
      const statusResponse = await axios.get(`/api/wallet/${selectedUserId}/status`);
      setWalletStatus(statusResponse.data);

      // Load credentials
      const credentialsResponse = await axios.get(`/api/wallet/${selectedUserId}/credentials`);
      setCredentials(credentialsResponse.data.credentials || []);
    } catch (err) {
      setError('Failed to load wallet data');
    } finally {
      setLoading(false);
    }
  };

  const provisionDemoCredentials = async () => {
    setLoading(true);
    setError(null);

    try {
      await axios.get(`/api/wallet/demo/provision/${selectedUserId}`);
      await loadWalletData(); // Reload data
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to provision demo credentials');
    } finally {
      setLoading(false);
    }
  };

  const deleteCredential = async (credentialId) => {
    try {
      await axios.delete(`/api/wallet/credentials/${credentialId}`);
      await loadWalletData(); // Reload data
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete credential');
    }
  };

  const viewCredentialDetails = async (credentialId) => {
    try {
      const response = await axios.get(`/api/wallet/credentials/${credentialId}`);
      setSelectedCredential(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load credential details');
    }
  };

  const simulateImportCredential = async () => {
    setLoading(true);
    setError(null);

    try {
      await axios.post(`/api/wallet/${selectedUserId}/import`, {
        import_method: 'openid4vci',
        credential_offer_uri: 'https://issuer.demo.local/offer/mock_credential_offer'
      });
      await loadWalletData(); // Reload data
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to import credential');
    } finally {
      setLoading(false);
    }
  };

  const getCredentialStatusColor = (status) => {
    switch (status?.toUpperCase()) {
      case 'ISSUED':
      case 'ACTIVE':
        return 'success';
      case 'EXPIRED':
        return 'error';
      case 'REVOKED':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        Digital Wallet Demo
      </Typography>

      <Typography variant="body1" color="text.secondary" paragraph>
        Manage mDoc and mDL credentials in a secure wallet using the OpenWallet Foundation Multipaz SDK.
        Store, view, and present credentials with user consent and selective disclosure.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Wallet Controls
              </Typography>

              <TextField
                fullWidth
                label="User ID"
                value={selectedUserId}
                onChange={(e) => setSelectedUserId(e.target.value)}
                sx={{ mb: 2 }}
              />

              {walletStatus && (
                <Paper sx={{ p: 2, mb: 2, bgcolor: 'grey.50' }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Wallet Status
                  </Typography>
                  <Typography variant="body2">
                    User: {walletStatus.user_id}
                  </Typography>
                  <Typography variant="body2">
                    Credentials: {walletStatus.credentials_count}
                  </Typography>
                  <Typography variant="body2">
                    Status: <Chip label={walletStatus.status} size="small" color="success" />
                  </Typography>
                  <Typography variant="body2">
                    Secure Area: <Chip label={walletStatus.secure_area_status} size="small" color="primary" />
                  </Typography>
                </Paper>
              )}

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Button
                  variant="contained"
                  onClick={provisionDemoCredentials}
                  disabled={loading}
                  startIcon={loading && <CircularProgress size={20} />}
                >
                  Provision Demo Credentials
                </Button>

                <Button
                  variant="outlined"
                  onClick={simulateImportCredential}
                  disabled={loading}
                  startIcon={<QrIcon />}
                >
                  Import Credential (Mock)
                </Button>

                <Button
                  variant="outlined"
                  onClick={loadWalletData}
                  disabled={loading}
                >
                  Refresh Wallet
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Stored Credentials
              </Typography>

              {error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {error}
                </Alert>
              )}

              {loading && (
                <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                  <CircularProgress />
                </Box>
              )}

              {!loading && credentials.length === 0 && (
                <Typography color="text.secondary" sx={{ textAlign: 'center', p: 3 }}>
                  No credentials found. Use "Provision Demo Credentials" to add some.
                </Typography>
              )}

              {!loading && credentials.length > 0 && (
                <List>
                  {credentials.map((credential) => (
                    <ListItem
                      key={credential.credential_id}
                      sx={{
                        border: 1,
                        borderColor: 'grey.300',
                        borderRadius: 1,
                        mb: 1
                      }}
                    >
                      <ListItemText
                        primary={credential.display_name}
                        secondary={
                          <Box>
                            <Typography variant="body2" color="text.secondary">
                              Type: {credential.document_type}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              Issuer: {credential.issuer}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              Issued: {new Date(credential.issued_at).toLocaleDateString()}
                            </Typography>
                            <Chip
                              label={credential.status}
                              size="small"
                              color={getCredentialStatusColor(credential.status)}
                              sx={{ mt: 1 }}
                            />
                          </Box>
                        }
                      />
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          onClick={() => viewCredentialDetails(credential.credential_id)}
                          sx={{ mr: 1 }}
                        >
                          <ViewIcon />
                        </IconButton>
                        <IconButton
                          edge="end"
                          onClick={() => deleteCredential(credential.credential_id)}
                          color="error"
                        >
                          <DeleteIcon />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>

          {selectedCredential && (
            <Card sx={{ mt: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Credential Details
                </Typography>

                <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Credential ID: {selectedCredential.credential_id}
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    Storage Type: {selectedCredential.storage_type}
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    Last Accessed: {new Date(selectedCredential.last_accessed).toLocaleString()}
                  </Typography>

                  <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                    Credential Data:
                  </Typography>
                  <Box component="pre" sx={{ fontSize: '0.75rem', overflow: 'auto' }}>
                    {JSON.stringify(selectedCredential.details, null, 2)}
                  </Box>
                </Paper>

                <Button
                  variant="outlined"
                  onClick={() => setSelectedCredential(null)}
                  sx={{ mt: 2 }}
                >
                  Close Details
                </Button>
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default WalletDemo;
