namespace ShazrinSonar.Processing
{
    public static class GeofenceManager
    {
        // Converted from DMS to Decimal Degrees
        private static readonly (double Lat, double Lon)[] Polygon = new[]
        {
            (2.928072, 101.335228), // A. 2°55'41.06"N 101°20'06.82"E
            (2.920997, 101.339667), // B. 2°55'15.59"N 101°20'22.80"E
            (2.923997, 101.342856), // C. 2°55'26.39"N 101°20'34.28"E
            (2.929503, 101.339189)  // D. 2°55'46.21"N 101°20'21.08"E
        };

        public static bool IsInside(double currentLat, double currentLon)
        {
            bool isInside = false;
            int j = Polygon.Length - 1;

            for (int i = 0; i < Polygon.Length; i++)
            {
                if (Polygon[i].Lon < currentLon && Polygon[j].Lon >= currentLon ||
                    Polygon[j].Lon < currentLon && Polygon[i].Lon >= currentLon)
                {
                    if (Polygon[i].Lat + (currentLon - Polygon[i].Lon) /
                        (Polygon[j].Lon - Polygon[i].Lon) *
                        (Polygon[j].Lat - Polygon[i].Lat) < currentLat)
                    {
                        isInside = !isInside;
                    }
                }
                j = i;
            }
            return isInside;
        }
    }
}