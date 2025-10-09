import React from 'react';
import {
  Typography,
  Card,
  CardContent,
  Grid,
  Chip,
  Box,
  List,
  ListItem,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import {
  AccountBalance as IssuerIcon,
  VerifiedUser as VerifierIcon,
  AccountBalanceWallet as WalletIcon,
  CheckCircle as CheckIcon
} from '@mui/icons-material';

function Home() {
  const features = [
    'ISO 18013-5 mDL (Mobile Driving License) support',
    'mDoc (Mobile Document) issuance and verification',
    'OpenID4VP (OpenID for Verifiable Presentations)',
    'Proximity presentation via Bluetooth Low Energy',
    'Selective disclosure of credential claims',
    'Integration with OpenWallet Foundation Multipaz SDK',
    'Kubernetes deployment with Kind support',
    'Mock secure area for credential storage'
  ];

  return (
    <Box>
      <Typography variant="h3" component="h1" gutterBottom>
        OpenWallet Foundation mDoc/mDL Demo
      </Typography>

      <Typography variant="h6" color="text.secondary" paragraph>
        A comprehensive demonstration of mDoc/mDL credential issuance, storage, and verification
        using the OpenWallet Foundation's Multipaz SDK in a Kubernetes environment.
      </Typography>

      <Grid container spacing={3} sx={{ mt: 2, mb: 4 }}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <IssuerIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h5" component="h2" gutterBottom>
                Issuer Service
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Issue mDoc and mDL credentials using the Multipaz SDK.
                Supports ISO 18013-5 compliant mobile driving licenses
                and generic mobile documents.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <VerifierIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h5" component="h2" gutterBottom>
                Verifier Service
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Verify credentials using OpenID4VP and ISO 18013-5 protocols.
                Supports multiple verification scenarios like age verification,
                driving license checks, and identity verification.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <WalletIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h5" component="h2" gutterBottom>
                Wallet Service
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Store and manage credentials in a secure area.
                Present credentials via OpenID4VP or proximity protocols
                with user consent and selective disclosure.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h5" component="h2" gutterBottom>
            Demo Features
          </Typography>
          <List>
            {features.map((feature, index) => (
              <ListItem key={index}>
                <ListItemIcon>
                  <CheckIcon color="success" />
                </ListItemIcon>
                <ListItemText primary={feature} />
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="h5" component="h2" gutterBottom>
            Technology Stack
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 2 }}>
            <Chip label="OpenWallet Foundation" color="primary" />
            <Chip label="Multipaz SDK 0.94.0" color="primary" />
            <Chip label="ISO 18013-5" variant="outlined" />
            <Chip label="OpenID4VP" variant="outlined" />
            <Chip label="mDoc/mDL" variant="outlined" />
            <Chip label="Kubernetes" color="secondary" />
            <Chip label="Kind" color="secondary" />
            <Chip label="Python FastAPI" variant="outlined" />
            <Chip label="React.js" variant="outlined" />
            <Chip label="PostgreSQL" variant="outlined" />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Home;
