import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { AppBar, Toolbar, Typography, Container, Box } from '@mui/material';

import Home from './components/Home';
import IssuerDemo from './components/IssuerDemo';
import VerifierDemo from './components/VerifierDemo';
import WalletDemo from './components/WalletDemo';
import EnhancedVerifierDemo from './components/EnhancedVerifierDemo';
import Navigation from './components/Navigation';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <AppBar position="static">
          <Toolbar>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              OpenWallet Foundation mDoc/mDL Demo
            </Typography>
          </Toolbar>
        </AppBar>

        <Container maxWidth="lg">
          <Box sx={{ my: 4 }}>
            <Navigation />

            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/issuer" element={<IssuerDemo />} />
              <Route path="/verifier" element={<VerifierDemo />} />
              <Route path="/wallet" element={<WalletDemo />} />
              <Route path="/enhanced" element={<EnhancedVerifierDemo />} />
            </Routes>
          </Box>
        </Container>
      </Router>
    </ThemeProvider>
  );
}

export default App;
