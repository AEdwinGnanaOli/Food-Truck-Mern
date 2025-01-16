import React, { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom';
import { Navbar, Container, Nav, Button, Card, Col } from 'react-bootstrap';
import axios from 'axios';
import { CiHeart } from "react-icons/ci";
import '../css/card.css'
function VendorProductFullDedails() {
  const [pop,setPop]=useState(false)
  const { id, token } = useParams()
  const navigate = useNavigate();
  const [vendorProducts, setVendorProducts] = useState([])
  const userId = sessionStorage.getItem('userid')
  const vendorId = sessionStorage.getItem('vendorid')
  const [userData, setUserData] = useState({ shopname: "", email: '', shopmobilenumber: '', shopaddress: "", file: "" })
  useEffect(() => {
    axios.get(`https://foot-trucks-react-js.onrender.com/productfulldetails/${id}/${token}`).then(product => {
      setVendorProducts([product.data.vendorProductDetails])
    })
  }, [])

  const handleCard = () => {
    axios.post(`https://foot-trucks-react-js.onrender.com/usercart/${userId}/${vendorId}/${id}`, userData).then((card) => {
      navigate(`/userhome`)

    }).catch(err => {
      console.log(err)
    })
    axios.post(`https://foot-trucks-react-js.onrender.com/userdetails/${userId}/${vendorId}/${id}`).then((result) => {
    }).catch((err) => {
      console.log(err)
    });
  }
  const onClicks = () => {
    setPop(true)
  }
  return (
    <div id='card'>
      {
        vendorProducts.map((vendor) => (
          <Col className=''>
            {/* Product Details Card Start */}
            <Card className='card'>
              <div className="fulldetails">
                <div className="shop-details">
                  <div className="shop-image">
                    <Card.Img variant="top" className='' src={`https://foot-trucks-react-js.onrender.com/images/${vendor.shopImage}`}/>
                  </div>
                  <div className="card-body">
                    <Card.Body >
                      <Card.Title className='card-title'>{vendor.shopname}</Card.Title>
                      <div className="vendor-fulldetails address">
                        <label className='text-center'><span>ShopAddress</span> <span>:</span></label>
                        <Card.Text>{vendor.shopaddress}</Card.Text>
                      </div>
                      <div className="vendor-fulldetails ">
                        <label className='text-center'><span>Contect Us </span> <span>:</span></label>
                        <Card.Text>{vendor.shopmobilenumber}</Card.Text>
                      </div>
                      <div className="vendor-fulldetails ">
                        <label className='text-center'><span>Start Time </span> <span>:</span></label>
                        <Card.Text>{vendor.starttime}</Card.Text>
                      </div>
                      <div className="vendor-fulldetails">
                        <label className='text-center'><span>Ending Time</span>  <span>:</span></label>
                        <Card.Text>{vendor.endtime}</Card.Text>
                      </div>
                    </Card.Body>
                  </div>
                </div>
                <div className="menu">
                  <div className="menu-image">
                    <Card.Img variant="top" src={`https://foot-trucks-react-js.onrender.com/images/${vendor.menuImage}`}/>
                  </div>
                </div>
              </div>
            </Card>
            {/* Product Details Card End */}
          </Col>
        ))
      }
    </div>
  )
}

export default VendorProductFullDedails