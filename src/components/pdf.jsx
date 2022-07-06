import { useState, useEffect } from 'react';
// import { useSearchParams } from 'react-router-dom';
import { useLocation } from 'react-router';
import { useNavigate } from 'react-router-dom';
import { Stack, Button, Page } from '@shopify/polaris';
import PDFComponent from "../components/pdfComponent";
// import Router from "next/router";

const PrintPDF = (props) => {
  const navigate = useNavigate();
  const { state } = useLocation();
  // const [searchParams, setSearchParams] = useSearchParams();
  const [awbs, setAwbs] = useState([])
  
  useEffect(() => {
    const { awbList } = state; // Read values passed on state
    
    setAwbs(awbList)
  })
  
  return (
    <Page>
      <div className="noprint">
        <Stack>
          <Stack.Item fill>
            <Button
              onClick={() => { navigate(-1) }}
            >Back</Button>
          </Stack.Item>
          <Stack.Item>
            <Button primary
              onClick={() => { window.print() }}
            >Print</Button>
          </Stack.Item>

        </Stack>

      </div>
      <div id="print">
        {Array.isArray(awbs) ? awbs.map(awb => <PDFComponent key={awb} awb={awb}></PDFComponent>) : <PDFComponent key={awbs} awb={awbs}></PDFComponent>}
      </div>
    </Page>
  )

}

export default PrintPDF;