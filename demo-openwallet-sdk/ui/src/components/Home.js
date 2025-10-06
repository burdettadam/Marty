import React from 'react';
import {
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Box,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import {
  Home as HomeIcon,
  CardMembership as CardIcon,
  VerifiedUser as VerifiedIcon,
  AccountBalanceWallet as WalletIcon,
  Star as StarIcon,
  Shield as ShieldIcon,
  QrCode as QrCodeIcon,
  Security as SecurityIcon,
  Policy as PolicyIcon
} from '@mui/icons-material';

const Home = () => {
  return (
    <Box>
      <Typography variant="h3" component="h1" gutterBottom align="center">
        <HomeIcon sx={{ fontSize: 48, mr: 2, verticalAlign: 'middle' }} />
        OpenWallet Foundation mDoc/mDL Demo
      </Typography>
      
      <Alert severity="info" sx={{ mb: 4 }}>
        <Typography variant="body1">
          This demonstration showcases the OpenWallet Foundation's approach to digital identity 
          using mobile documents (mDoc) and mobile driving licenses (mDL) based on ISO 18013-5 standards.
        </Typography>
      </Alert>

      <Grid container spacing={4}>
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h5" component="h2" gutterBottom>
                <CardIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Core Demo Features
              </Typography>
              
              <List>
                <ListItem>
                  <ListItemIcon>
                    <CardIcon color="primary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Credential Issuance" 
                    secondary="Issue mDL credentials using OpenWallet Foundation SDK"
                  />
                </ListItem>
                
                <ListItem>
                  <ListItemIcon>
                    <VerifiedIcon color="primary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Credential Verification" 
                    secondary="Verify presentations with OpenID4VP protocol"
                  />
                </ListItem>
                
                <ListItem>
                  <ListItemIcon>
                    <WalletIcon color="primary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Wallet Management" 
                    secondary="Store and manage digital credentials securely"
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h5" component="h2" gutterBottom>
                <StarIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Enhanced Features
              </Typography>
              
              <List>
                <ListItem>
                  <ListItemIcon>
                    <ShieldIcon color="secondary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Age Verification" 
                    secondary="Verify age without disclosing birth date using selective disclosure"
                  />
                </ListItem>
                
                <ListItem>
                  <ListItemIcon>
                    <QrCodeIcon color="secondary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Offline QR Verification" 
                    secondary="Verify credentials without network connectivity"
                  />
                </ListItem>
                
                <ListItem>
                  <ListItemIcon>
                    <SecurityIcon color="secondary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Certificate Monitoring" 
                    secondary="Monitor mDL Document Signer Certificate lifecycle"
                  />
                </ListItem>
                
                <ListItem>
                  <ListItemIcon>
                    <PolicyIcon color="secondary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Policy-Based Disclosure" 
                    secondary="Context-aware attribute sharing using authorization engine"
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h5" component="h2" gutterBottom>
                Technology Stack
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center" p={2}>
                    <Typography variant="h6" color="primary">OpenWallet Foundation</Typography>
                    <Typography variant="body2">Multipaz SDK v0.94.0</Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center" p={2}>
                    <Typography variant="h6" color="primary">ISO 18013-5</Typography>
                    <Typography variant="body2">mDL Standards</Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center" p={2}>
                    <Typography variant="h6" color="primary">OpenID4VP</Typography>
                    <Typography variant="body2">Presentation Protocol</Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center" p={2}>
                    <Typography variant="h6" color="primary">Kubernetes</Typography>
                    <Typography variant="body2">Cloud-Native Deployment</Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Box textAlign="center">
            <Typography variant="h6" gutterBottom>
              Get Started
            </Typography>
            <Typography variant="body1" color="text.secondary" gutterBottom>
              Explore the demo features using the navigation tabs above. Start with the Issuer 
              to create credentials, then use the Verifier to validate them, or check out the 
              Enhanced features for advanced capabilities.
            </Typography>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Home;