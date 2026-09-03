import React from 'react';
import { ActiveDetectors } from '../../types';
import { DETECTORS_LIST } from '../../utils/constants';

interface DetectorGridProps { activeDetectors?: ActiveDetectors; }

export const DetectorGrid: React.FC<DetectorGridProps> = ({ activeDetectors }) => <div className="card detection-fabric">
  <div className="fabric-header"><strong>Streaming detection fabric</strong><span>Six independent signals · 300 s correlation window</span></div>
  <div className="fabric-stage" aria-label="Six detection engines converging on a fused risk score">
    <div className="fabric-core"><strong>Fused risk<br />score</strong><span>Confidence 98%</span></div>
    {[0, 1, 2, 3, 4, 5].map((index) => {
      const detector = DETECTORS_LIST[index];
      const active = activeDetectors ? activeDetectors[detector.id] : true;
      return <div className={`detector-node node-${index}`} key={detector.id} style={{ opacity: active ? 1 : .42 }}><div className="node-top"><i /> {detector.shortName}</div><small>{detector.category}</small><small>{active ? 'Signal streaming' : 'Engine offline'}</small></div>;
    })}
    <div className="fabric-line one" /><div className="fabric-line two" /><div className="fabric-line three" /><div className="fabric-line four" /><div className="fabric-line five" /><div className="fabric-line six" />
    <i className="fabric-particle particle-a" /><i className="fabric-particle particle-b" /><i className="fabric-particle particle-c" /><i className="fabric-particle particle-d" />
  </div>
</div>;
