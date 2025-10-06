import React from 'react';
import { Tabs, Tab, Box } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';

function Navigation() {
  const location = useLocation();
  
  const getCurrentTab = () => {
    switch (location.pathname) {
      case '/issuer':
        return 1;
      case '/verifier':
        return 2;
      case '/wallet':
        return 3;
      default:
        return 0;
    }
  };

  return (
    <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
      <Tabs value={getCurrentTab()} aria-label="demo navigation">
        <Tab label="Home" component={Link} to="/" />
        <Tab label="Issuer" component={Link} to="/issuer" />
        <Tab label="Verifier" component={Link} to="/verifier" />
        <Tab label="Wallet" component={Link} to="/wallet" />
      </Tabs>
    </Box>
  );
}

export default Navigation;