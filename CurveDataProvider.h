#ifndef CURVEDATAPROVIDER_H
#define CURVEDATAPROVIDER_H

#include "qwt_series_data.h"

class curveProvider : public QwtSeriesData<QPointF>
{
  public:
    curveProvider()
    {

    }

    void setSamples( std::vector<unsigned char> &samp)
    {
        dataSamples.swap(samp);
    }

    virtual size_t size() const
    {
        return dataSamples.size();
    }

    virtual QPointF sample( size_t i ) const
    {
        return QPointF( i, dataSamples[i]);
    }

    virtual QRectF boundingRect() const
    {
        return QRectF();
    }

private:
    std::vector<unsigned char> dataSamples;
};

#endif // CURVEDATAPROVIDER_H
